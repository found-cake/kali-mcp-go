package executor

func (r *Result) Success() bool {
	return !r.TimedOut && !r.Cancelled && r.ReturnCode == 0
}
