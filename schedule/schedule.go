// Package schedule declares recurring workflows idempotently from a worker's
// startup, so the schedule lives beside the workflow it runs and cannot be
// forgotten when a cluster is rebuilt.
//
// Every scheduled run is bounded. A schedule fires into a fixed workflow id
// under an overlap policy of skip, so a run that never finishes is not one
// lost pass, it is every pass from then on. The execution timeout declared on
// the workflow type does not apply here -- a schedule action carries its own
// start options and inherits nothing -- so the bound is set on the action, or
// there is no bound at all.
package schedule

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
)

// DefaultExecutionTimeout bounds a run when the caller does not say.
const DefaultExecutionTimeout = 30 * time.Minute

// Spec describes a recurring workflow. Build it with New and Options.
type Spec struct {
	// ID of the schedule.
	ID string
	// Cron expression, in Temporal's cron dialect.
	Cron string
	// TimeZone the cron is evaluated in. Empty is UTC.
	TimeZone string
	// Workflow type name, TaskQueue and WorkflowID of each run.
	Workflow   string
	TaskQueue  string
	WorkflowID string
	// Args passed to every run.
	Args []any
	// ExecutionTimeout bounds one run. Never zero after New.
	ExecutionTimeout time.Duration
	// Overlap decides what happens when a run is still going at the next
	// fire. Default skip.
	Overlap enumspb.ScheduleOverlapPolicy
	// CatchupWindow is how far back a missed fire is still worth running.
	// Default one minute: the next run supersedes a missed one.
	CatchupWindow time.Duration
	// Logger reports creates and updates. Default slog.Default().
	Logger *slog.Logger
}

// Option adjusts a Spec.
type Option func(*Spec)

// WithArgs sets the arguments every run receives.
func WithArgs(args ...any) Option { return func(s *Spec) { s.Args = args } }

// WithExecutionTimeout bounds one run.
func WithExecutionTimeout(d time.Duration) Option { return func(s *Spec) { s.ExecutionTimeout = d } }

// WithTimeZone evaluates the cron in a named zone, e.g. "America/Los_Angeles".
func WithTimeZone(tz string) Option { return func(s *Spec) { s.TimeZone = tz } }

// WithOverlap sets the overlap policy.
func WithOverlap(p enumspb.ScheduleOverlapPolicy) Option { return func(s *Spec) { s.Overlap = p } }

// WithCatchupWindow sets how far back a missed fire is still run.
func WithCatchupWindow(d time.Duration) Option { return func(s *Spec) { s.CatchupWindow = d } }

// WithWorkflowID fixes the id each run uses. Default is the schedule id.
func WithWorkflowID(id string) Option { return func(s *Spec) { s.WorkflowID = id } }

// WithLogger sets where creates and updates are reported.
func WithLogger(l *slog.Logger) Option { return func(s *Spec) { s.Logger = l } }

// New builds a Spec. id, cron, workflow and taskQueue are the parts no
// schedule can do without.
func New(id, cron, workflow, taskQueue string, opts ...Option) (Spec, error) {
	s := Spec{
		ID: id, Cron: cron, Workflow: workflow, TaskQueue: taskQueue, WorkflowID: id,
		ExecutionTimeout: DefaultExecutionTimeout,
		Overlap:          enumspb.SCHEDULE_OVERLAP_POLICY_SKIP,
		CatchupWindow:    time.Minute,
		Logger:           slog.Default(),
	}
	for _, o := range opts {
		o(&s)
	}
	switch {
	case s.ID == "" || s.Cron == "" || s.Workflow == "" || s.TaskQueue == "":
		return s, errors.New("schedule: id, cron, workflow and task queue are required")
	case s.ExecutionTimeout <= 0:
		return s, fmt.Errorf("schedule %s: execution timeout must be positive; an unbounded run blocks every run after it", s.ID)
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	return s, nil
}

// Ensure creates the schedule if it is absent and updates its cron, time zone
// and execution timeout if they have drifted. Idempotent: every replica runs
// it, and all but the first find it already there.
func Ensure(ctx context.Context, c client.Client, s Spec) error {
	if s.ExecutionTimeout <= 0 {
		return fmt.Errorf("schedule %s: execution timeout must be positive", s.ID)
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	handle := c.ScheduleClient().GetHandle(ctx, s.ID)
	desc, err := handle.Describe(ctx)
	switch {
	case err == nil:
		return updateIfDrifted(ctx, handle, desc, s)
	case isNotFound(err):
	default:
		return err
	}

	_, err = c.ScheduleClient().Create(ctx, client.ScheduleOptions{
		ID:   s.ID,
		Spec: client.ScheduleSpec{CronExpressions: []string{s.Cron}, TimeZoneName: s.TimeZone},
		Action: &client.ScheduleWorkflowAction{
			ID:                       s.WorkflowID,
			Workflow:                 s.Workflow,
			TaskQueue:                s.TaskQueue,
			Args:                     s.Args,
			WorkflowExecutionTimeout: s.ExecutionTimeout,
		},
		Overlap:       s.Overlap,
		CatchupWindow: s.CatchupWindow,
	})
	if err != nil && !isAlreadyStarted(err) {
		return err
	}
	s.Logger.InfoContext(ctx, "temporal schedule created", "id", s.ID, "cron", s.Cron, "execution_timeout", s.ExecutionTimeout)
	return nil
}

func updateIfDrifted(ctx context.Context, handle client.ScheduleHandle, desc *client.ScheduleDescription, s Spec) error {
	current := desc.Schedule.Spec.CronExpressions
	cronOK := len(current) == 1 && current[0] == s.Cron && desc.Schedule.Spec.TimeZoneName == s.TimeZone
	action, _ := desc.Schedule.Action.(*client.ScheduleWorkflowAction)
	timeoutOK := action != nil && action.WorkflowExecutionTimeout == s.ExecutionTimeout
	if cronOK && timeoutOK {
		s.Logger.InfoContext(ctx, "temporal schedule current", "id", s.ID, "cron", s.Cron)
		return nil
	}
	s.Logger.InfoContext(ctx, "updating temporal schedule", "id", s.ID, "from", current, "to", s.Cron, "execution_timeout", s.ExecutionTimeout)
	return handle.Update(ctx, client.ScheduleUpdateOptions{
		DoUpdate: func(in client.ScheduleUpdateInput) (*client.ScheduleUpdate, error) {
			in.Description.Schedule.Spec = &client.ScheduleSpec{CronExpressions: []string{s.Cron}, TimeZoneName: s.TimeZone}
			if a, ok := in.Description.Schedule.Action.(*client.ScheduleWorkflowAction); ok {
				a.WorkflowExecutionTimeout = s.ExecutionTimeout
			}
			return &client.ScheduleUpdate{Schedule: &in.Description.Schedule}, nil
		},
	})
}

func isNotFound(err error) bool {
	var nf *serviceerror.NotFound
	return errors.As(err, &nf)
}

func isAlreadyStarted(err error) bool {
	var exists *serviceerror.WorkflowExecutionAlreadyStarted
	if errors.As(err, &exists) {
		return true
	}
	var already *serviceerror.AlreadyExists
	return errors.As(err, &already)
}
