package peer

import "fmt"

// Proc identifies a process. PID plus start time is unique in practice; a PID
// alone is reused.
type Proc struct {
	PID     int
	StartUS uint64
	Name    string
}

func (p Proc) String() string { return fmt.Sprintf("%s (pid %d)", p.Name, p.PID) }
