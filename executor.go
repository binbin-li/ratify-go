/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ratify

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	"oras.land/oras-go/v2/registry"
)

// errSubjectPruned is returned when the evaluator does not need given subject
// to be verified to make a decision by [Evaluator.Pruned].
var errSubjectPruned = errors.New("evaluator sub-graph is pruned for the subject")

// concurrentTaskQueue is a thread-safe task queue for concurrent processing
type concurrentTaskQueue struct {
	mu    sync.Mutex
	tasks []*executorTask
	cond  *sync.Cond
	done  bool
}

func newConcurrentTaskQueue() *concurrentTaskQueue {
	q := &concurrentTaskQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *concurrentTaskQueue) isEmpty() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.tasks) == 0 && !q.done
}

func (q *concurrentTaskQueue) push(tasks ...*executorTask) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.done {
		return // Don't add tasks to a closed queue
	}
	q.tasks = append(q.tasks, tasks...)
	q.cond.Broadcast()
}

func (q *concurrentTaskQueue) pop() (task *executorTask, success bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for len(q.tasks) == 0 && !q.done {
		q.cond.Wait()
	}

	if len(q.tasks) == 0 {
		return nil, false
	}

	task = q.tasks[len(q.tasks)-1]
	q.tasks = q.tasks[:len(q.tasks)-1]
	return task, true
}

func (q *concurrentTaskQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.done = true
	q.cond.Broadcast()
}

// concurrencyController manages the available goroutine slots
type concurrencyController struct {
	semaphore chan struct{}
}

func newConcurrencyController(maxConcurrency int) *concurrencyController {
	if maxConcurrency <= 1 {
		return &concurrencyController{}
	}
	return &concurrencyController{
		semaphore: make(chan struct{}, maxConcurrency-1),
	}
}

func (c *concurrencyController) release() {
	if c.semaphore != nil {
		<-c.semaphore
	}
}

func (c *concurrencyController) tryAcquire() bool {
	if c.semaphore == nil {
		return false
	}

	select {
	case c.semaphore <- struct{}{}:
		return true
	default:
		return false
	}
}

// executionContext holds the shared context for concurrent execution
type executionContext struct {
	ctx            context.Context
	cancel         context.CancelFunc
	taskQueue      *concurrentTaskQueue
	concurrency    *concurrencyController
	evaluator      Evaluator
	repo           string
	referenceTypes []string
	executor       *Executor
	atomicErr      atomic.Value // stores error atomically
	workInProgress atomic.Int64 // Counter for active goroutines processing tasks
}

// ValidateArtifactOptions describes the artifact validation options.
type ValidateArtifactOptions struct {
	// Subject is the reference of the artifact to be validated. Required.
	Subject string

	// ReferenceTypes is a list of reference types that should be verified
	// against in associated artifacts. Empty list means all artifacts should be
	// verified. Optional.
	ReferenceTypes []string
}

// ValidationResult aggregates verifier reports and the final verification
// result evaluated by the policy enforcer.
type ValidationResult struct {
	// Succeeded represents the outcome determined by the policy enforcer based
	// on the aggregated verifier reports. And if an error occurs during the
	// validation process prior to policy evaluation, it will be set to `false`.
	// If the policy enforcer is not set in the executor, this field will be set
	// to `false`. In such cases, this field should be ignored. Required.
	Succeeded bool

	// ArtifactReports is aggregated reports of verifying associated artifacts.
	// This field can be nil if an error occured during validation or no reports
	// were generated. Optional.
	ArtifactReports []*ValidationReport
}

// Executor is defined to validate artifacts.
type Executor struct {
	// Executor should configure exactly one store to fetch supply chain
	// content. Required.
	Store Store

	// Executor could use multiple verifiers to validate artifacts. Required.
	Verifiers []Verifier

	// Executor should have at most one policy enforcer to evalute reports. If
	// not set, the validation result will be returned without evaluation.
	// Optional.
	PolicyEnforcer PolicyEnforcer

	// MaxConcurrency is the maximum number of goroutines that can be created
	// for each artifact validation request. If set to 1, single thread mode is
	// used. If set to 0, defaults to runtime.NumCPU().
	// Optional.
	MaxConcurrency int
}

// NewExecutor creates a new executor with the given verifiers, store, and
// policy enforcer.
func NewExecutor(store Store, verifiers []Verifier, policyEnforcer PolicyEnforcer, maxConcurrency int) (*Executor, error) {
	if err := validateExecutorSetup(store, verifiers); err != nil {
		return nil, err
	}
	if maxConcurrency < 0 {
		return nil, fmt.Errorf("maxConcurrency must be non-negative, got %d", maxConcurrency)
	}
	if maxConcurrency == 0 {
		maxConcurrency = runtime.NumCPU() // default to number of CPUs
	}

	return &Executor{
		Store:          store,
		Verifiers:      verifiers,
		PolicyEnforcer: policyEnforcer,
		MaxConcurrency: maxConcurrency,
	}, nil
}

// ValidateArtifact returns the result of verifying an artifact.
func (e *Executor) ValidateArtifact(ctx context.Context, opts ValidateArtifactOptions) (*ValidationResult, error) {
	if err := validateExecutorSetup(e.Store, e.Verifiers); err != nil {
		return nil, err
	}

	aggregatedVerifierReports, evaluator, err := e.aggregateVerifierReports(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate and aggregate verifier reports: %w", err)
	}

	if evaluator == nil {
		return &ValidationResult{
			Succeeded:       false,
			ArtifactReports: aggregatedVerifierReports,
		}, nil
	}

	decision, err := evaluator.Evaluate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate verifier reports: %w", err)
	}

	return &ValidationResult{
		Succeeded:       decision,
		ArtifactReports: aggregatedVerifierReports,
	}, nil
}

// aggregateVerifierReports generates and aggregates all verifier reports.
func (e *Executor) aggregateVerifierReports(ctx context.Context, opts ValidateArtifactOptions) ([]*ValidationReport, Evaluator, error) {
	// Only resolve the root subject reference.
	ref, desc, err := e.resolveSubject(ctx, opts.Subject)
	if err != nil {
		return nil, nil, err
	}
	repo := ref.Registry + "/" + ref.Repository

	var evaluator Evaluator
	if e.PolicyEnforcer != nil {
		evaluator, err = e.PolicyEnforcer.Evaluator(ctx, ref.Reference)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create a new evaluator: %w", err)
		}
	}

	// Enqueue the subject artifact as the first task.
	rootTask := &executorTask{
		artifact:     ref,
		artifactDesc: desc,
		subjectReport: &ValidationReport{
			Artifact: desc,
		},
	}

	return e.processVerifierReports(ctx, rootTask, repo, opts.ReferenceTypes, evaluator)
}

// processVerifierReports handles concurrent processing
func (e *Executor) processVerifierReports(ctx context.Context, rootTask *executorTask, repo string, referenceTypes []string, evaluator Evaluator) ([]*ValidationReport, Evaluator, error) {
	// Create execution context with cancellation

	execContext := &executionContext{
		ctx:            ctx,
		taskQueue:      newConcurrentTaskQueue(),
		concurrency:    newConcurrencyController(e.MaxConcurrency),
		evaluator:      evaluator,
		repo:           repo,
		referenceTypes: referenceTypes,
		executor:       e,
	}

	// Start with the root task
	execContext.taskQueue.push(rootTask)

	execContext.processTasks()

	execContext.taskQueue.close()

	// Check for errors
	if errVal := execContext.atomicErr.Load(); errVal != nil {
		return nil, nil, errVal.(error)
	}

	return rootTask.subjectReport.ArtifactReports, evaluator, nil
}

// processTasks processes all tasks by spawning goroutines for each task
func (execCtx *executionContext) processTasks() {
	baseCtx, cancel := context.WithCancel(execCtx.ctx)
	defer cancel()

	g, ctx := errgroup.WithContext(baseCtx)

	var wg sync.WaitGroup
LOOP:
	for {
		// Increment work counter before popping to prevent race condition
		// where queue becomes empty but work hasn't started yet
		execCtx.startVerifySubject()
		task, ok := execCtx.taskQueue.pop()
		if !ok {
			// Queue was closed and is empty, we're done
			// Decrement the counter since we didn't actually get work
			execCtx.finishedVerifySubject()
			break
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			execCtx.finishedVerifySubject()
			break LOOP
		default:
		}

		// Try to acquire a slot for processing this task
		if execCtx.concurrency.tryAcquire() {
			// Process the task in a separate goroutine
			wg.Add(1)
			task := task // Capture loop variable
			g.Go(func() error {
				defer func() {
					execCtx.concurrency.release()
					execCtx.finishedVerifySubject()
					wg.Done()
				}()

				if err := execCtx.executor.verifySubjectAgainstReferrers(execCtx, task); err != nil {
					execCtx.setError(err)
					execCtx.cancel() // Cancel context to stop other workers
					return
				}
			})
		} else {
			// If no slots available, process in current goroutine
			err := execCtx.executor.verifySubjectAgainstReferrers(execCtx, task)
			if err != nil {
				execCtx.setError(err)
				execCtx.cancel()
				execCtx.finishedVerifySubject()
				break
			}
			execCtx.finishedVerifySubject()
		}
	}

	// Wait for all spawned goroutines to complete
	wg.Wait()
}

// finishedVerifySubject checks if we should close the queue to signal termination
func (execCtx *executionContext) finishedVerifySubject() {
	execCtx.workInProgress.Add(-1)
	if execCtx.taskQueue.isEmpty() && execCtx.workInProgress.Load() == 0 {
		execCtx.taskQueue.close()
	}
}

func (execCtx *executionContext) startVerifySubject() {
	execCtx.workInProgress.Add(1)
}

// setError safely sets an error in the execution context
func (execCtx *executionContext) setError(err error) {
	execCtx.atomicErr.CompareAndSwap(nil, err)
}

// processReferrer processes a single referrer artifact and creates a new task
func (e *Executor) processReferrer(execCtx *executionContext, task *executorTask, referrer ocispec.Descriptor, artifact string, addArtifactReport func(*ValidationReport)) error {
	results, err := e.verifyArtifact(execCtx, execCtx.repo, task.artifactDesc, referrer)
	if err != nil {
		if errors.Is(err, errSubjectPruned) && len(results) > 0 {
			artifactReport := &ValidationReport{
				Subject:  artifact,
				Results:  results,
				Artifact: referrer,
			}
			addArtifactReport(artifactReport)
		}
		return err
	}

	artifactReport := &ValidationReport{
		Subject:  artifact,
		Results:  results,
		Artifact: referrer,
	}
	addArtifactReport(artifactReport)

	// Create and immediately push new task to queue
	referrerArtifact := task.artifact
	referrerArtifact.Reference = referrer.Digest.String()
	newTask := &executorTask{
		artifact:      referrerArtifact,
		artifactDesc:  referrer,
		subjectReport: artifactReport,
	}
	execCtx.taskQueue.push(newTask)
	return nil
}

// verifySubjectAgainstReferrers verifies the subject artifact against all
// referrers in the store concurrently and produces new tasks for each referrer.
func (e *Executor) verifySubjectAgainstReferrers(execCtx *executionContext, task *executorTask) error {
	artifact := task.artifact.String()

	var artifactReports []*ValidationReport
	var mu sync.Mutex

	addArtifactReport := func(report *ValidationReport) {
		mu.Lock()
		artifactReports = append(artifactReports, report)
		mu.Unlock()
	}

	err := e.Store.ListReferrers(execCtx.ctx, artifact, execCtx.referenceTypes, func(referrers []ocispec.Descriptor) error {
		// Process referrers concurrently with cancellation
		ctx, cancel := context.WithCancel(execCtx.ctx)
		defer cancel()

		var wg sync.WaitGroup
		var firstErr atomic.Value

		setError := func(err error) {
			if firstErr.CompareAndSwap(nil, err) {
				cancel() // Cancel context to stop other goroutines
			}
		}

		// Process referrers in parallel
		for _, referrer := range referrers {
			// Check if context is cancelled before processing each referrer
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Check if we can acquire a goroutine slot
			if execCtx.concurrency.tryAcquire() {
				// Process concurrently
				wg.Add(1)
				go func(referrer ocispec.Descriptor) {
					defer func() {
						execCtx.concurrency.release()
						wg.Done()
					}()

					if err := e.processReferrer(execCtx, task, referrer, artifact, addArtifactReport); err != nil {
						setError(err)
						return
					}
				}(referrer)
			} else {
				// If no slot available, process serially
				if err := e.processReferrer(execCtx, task, referrer, artifact, addArtifactReport); err != nil {
					setError(err)
					return err
				}
			}
		}

		wg.Wait()
		if err := firstErr.Load(); err != nil {
			return err.(error)
		}
		return nil
	})

	if err != nil {
		if err != errSubjectPruned {
			return fmt.Errorf("failed to verify referrers for artifact %s: %w", artifact, err)
		}
	}

	if execCtx.evaluator != nil {
		if err := execCtx.evaluator.Commit(execCtx.ctx, task.artifactDesc.Digest.String()); err != nil {
			return fmt.Errorf("failed to commit the artifact %s: %w", artifact, err)
		}
	}

	task.subjectReport.ArtifactReports = append(task.subjectReport.ArtifactReports, artifactReports...)
	return nil
}

// verifyArtifact verifies the artifact by all configured verifiers concurrently
func (e *Executor) verifyArtifact(execCtx *executionContext, repo string, subjectDesc, artifact ocispec.Descriptor) ([]*VerificationResult, error) {
	var verifierReports []*VerificationResult
	var mu sync.Mutex

	// Check early termination conditions first
	if execCtx.evaluator != nil {
		prunedState, err := execCtx.evaluator.Pruned(execCtx.ctx, subjectDesc.Digest.String(), artifact.Digest.String(), "")
		if err != nil {
			return nil, fmt.Errorf("failed to check if artifact is pruned: %w", err)
		}
		switch prunedState {
		case PrunedStateArtifactPruned:
			return verifierReports, nil
		case PrunedStateSubjectPruned:
			return verifierReports, errSubjectPruned
		}
	}

	// Collect applicable verifiers
	var applicableVerifiers []Verifier
	for _, verifier := range e.Verifiers {
		if verifier.Verifiable(artifact) {
			applicableVerifiers = append(applicableVerifiers, verifier)
		}
	}

	if len(applicableVerifiers) == 0 {
		return verifierReports, nil
	}

	// Process verifiers concurrently with cancellation
	ctx, cancel := context.WithCancel(execCtx.ctx)
	defer cancel()

	var wg sync.WaitGroup
	var firstErr atomic.Value

	setError := func(err error) {
		if firstErr.CompareAndSwap(nil, err) {
			cancel() // Cancel context to stop other goroutines
		}
	}

	for _, verifier := range applicableVerifiers {
		// Check if context is cancelled before processing each verifier
		select {
		case <-ctx.Done():
			return verifierReports, ctx.Err()
		default:
		}

		// Check if we can acquire a goroutine slot
		if !execCtx.concurrency.tryAcquire() {
			// If no slot available, process serially
			verifierReport, err := e.processVerifier(ctx, verifier, repo, subjectDesc, artifact, execCtx.evaluator)
			if err != nil {
				if errors.Is(err, errSubjectPruned) {
					return verifierReports, errSubjectPruned
				}
				return nil, err
			}
			if verifierReport != nil {
				verifierReports = append(verifierReports, verifierReport)
			}
		} else {
			// Process concurrently
			v := verifier // Capture loop variable
			wg.Add(1)
			go func() {
				defer func() {
					execCtx.concurrency.release()
					wg.Done()
				}()

				// Check if context is cancelled before starting work
				select {
				case <-ctx.Done():
					setError(ctx.Err())
					return
				default:
				}

				verifierReport, err := e.processVerifier(ctx, v, repo, subjectDesc, artifact, execCtx.evaluator)
				if err != nil {
					setError(err)
					return
				}

				if verifierReport != nil {
					mu.Lock()
					verifierReports = append(verifierReports, verifierReport)
					mu.Unlock()
				}
			}()
		}
	}

	wg.Wait()

	if err := firstErr.Load(); err != nil {
		return verifierReports, err.(error)
	}

	return verifierReports, nil
}

// processVerifier handles individual verifier processing
func (e *Executor) processVerifier(ctx context.Context, verifier Verifier, repo string, subjectDesc, artifact ocispec.Descriptor, evaluator Evaluator) (*VerificationResult, error) {
	if evaluator != nil {
		prunedState, err := evaluator.Pruned(ctx, subjectDesc.Digest.String(), artifact.Digest.String(), verifier.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to check if verifier: %s is required to verify subject: %s, against artifact: %s, err: %w", verifier.Name(), subjectDesc.Digest, artifact.Digest, err)
		}
		switch prunedState {
		case PrunedStateVerifierPruned:
			// Skip this verifier if it's not required.
			return nil, nil
		case PrunedStateArtifactPruned:
			// Skip remaining verifiers if the artifact is not required.
			return nil, nil
		case PrunedStateSubjectPruned:
			// Skip remaining verifiers and return `errSubjectPruned` to
			// notify `ListReferrers`stop processing.
			return nil, errSubjectPruned
		default:
			// do nothing if it's not pruned.
		}
	}

	// Verify the subject artifact against the referrer artifact.
	verifierReport, err := verifier.Verify(ctx, &VerifyOptions{
		Store:              e.Store,
		Repository:         repo,
		SubjectDescriptor:  subjectDesc,
		ArtifactDescriptor: artifact,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify artifact %s@%s with verifier %s: %w", repo, subjectDesc.Digest, verifier.Name(), err)
	}

	if evaluator != nil {
		if err := evaluator.AddResult(ctx, subjectDesc.Digest.String(), artifact.Digest.String(), verifierReport); err != nil {
			return nil, fmt.Errorf("failed to add verifier report for artifact %s@%s verified by verifier %s: %w", repo, subjectDesc.Digest, verifier.Name(), err)
		}
	}

	return verifierReport, nil
}

func (e *Executor) resolveSubject(ctx context.Context, subject string) (registry.Reference, ocispec.Descriptor, error) {
	ref, err := registry.ParseReference(subject)
	if err != nil {
		return registry.Reference{}, ocispec.Descriptor{}, fmt.Errorf("failed to parse subject reference %s: %w", subject, err)
	}

	artifactDesc, err := e.Store.Resolve(ctx, ref.String())
	if err != nil {
		return registry.Reference{}, ocispec.Descriptor{}, fmt.Errorf("failed to resolve subject reference %s: %w", ref.Reference, err)
	}
	ref.Reference = artifactDesc.Digest.String()
	return ref, artifactDesc, nil
}

// executorTask is a struct that represents a executorTask that verifies an artifact by
// the executor.
type executorTask struct {
	// artifact is the digested reference of the referrer artifact that will be
	// verified against.
	artifact registry.Reference

	// artifactDesc is the descriptor of the referrer artifact that will be
	// verified against.
	artifactDesc ocispec.Descriptor

	// subjectReport is the report of the subject artifact.
	subjectReport *ValidationReport
}

func validateExecutorSetup(store Store, verifiers []Verifier) error {
	if store == nil {
		return fmt.Errorf("store must be configured")
	}
	if len(verifiers) == 0 {
		return fmt.Errorf("at least one verifier must be configured")
	}
	return nil
}
