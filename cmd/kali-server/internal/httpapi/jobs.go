package httpapi

import (
	"encoding/json"
	"errors"

	"github.com/found-cake/kali-mcp-go/internal/jobs"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

const jobStoreLocalKey = "job-store"

func JobStoreMiddleware(store *jobs.Store) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals(jobStoreLocalKey, store)
		return c.Next()
	}
}

func JobStore(c fiber.Ctx) *jobs.Store {
	store, _ := c.Locals(jobStoreLocalKey).(*jobs.Store)
	return store
}

func HandleJobStatus(c fiber.Ctx) error {
	return handleJobLookup(c)
}

func HandleJobResult(c fiber.Ctx) error {
	return handleJobLookup(c)
}

func HandleJobCancel(c fiber.Ctx) error {
	store := JobStore(c)
	if store == nil {
		return InternalServerError(c, "job store unavailable")
	}
	snapshot, err := store.Cancel(c.Params("id"))
	return writeJobResponse(c, snapshot, err)
}

func handleJobLookup(c fiber.Ctx) error {
	store := JobStore(c)
	if store == nil {
		return InternalServerError(c, "job store unavailable")
	}
	snapshot, err := store.Get(c.Params("id"))
	return writeJobResponse(c, snapshot, err)
}

func writeJobResponse(c fiber.Ctx, snapshot jobs.Snapshot, err error) error {
	if errors.Is(err, jobs.ErrNotFound) {
		data, marshalErr := json.Marshal(dto.JobLookupFailure{
			Code: "job_not_found_or_expired", Message: "job not found or its terminal result retention expired",
		})
		if marshalErr != nil {
			return InternalServerError(c, "encode job lookup failure")
		}
		return c.Status(fiber.StatusNotFound).JSON(dto.JobResponse{
			JobID: c.Params("id"), Status: dto.JobError, Data: data,
		})
	}
	if err != nil {
		return InternalServerError(c, err.Error())
	}
	response, err := snapshot.Response()
	if err != nil {
		return InternalServerError(c, err.Error())
	}
	return c.JSON(response)
}
