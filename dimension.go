package main

import "fmt"

type Dimension struct {
	Type  DimensionType
	Value string
}

type DimensionType int

const (
	DimensionBackend DimensionType = 1 << iota
	DimensionFrontend
	DimensionHost
	DimensionService
)

func (t *DimensionType) UnmarshalText(b []byte) error {
	s := string(b)
	switch s {
	case "backend":
		*t = DimensionBackend
	case "frontend":
		*t = DimensionFrontend
	case "host":
		*t = DimensionHost
	case "service":
		*t = DimensionService
	default:
		return fmt.Errorf("Unrecognized dimension type %s\n", s)
	}
	return nil
}
