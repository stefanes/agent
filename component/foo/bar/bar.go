package bar

import (
	"context"
	"fmt"
	"sync"

	"github.com/grafana/agent/component"
)

func init() {
	component.Register(component.Registration{
		Name:    "foo.bar",
		Args:    Arguments{},
		Exports: Exports{},

		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

// Arguments holds values which are used to configure the discovery.transformer component.
type Arguments struct {
	InValue string `hcl:"val"`
}

// Exports holds values which are exported by the discovery.transformer component.
type Exports struct {
	OutVal string `hcl:"val"`
}

// Component implements the discovery.transformer component.
type Component struct {
	opts component.Options
	mut  sync.Mutex
	args Arguments
}

var (
	_ component.Component = (*Component)(nil)
)

// New creates a new discovery.transformer component.
func New(o component.Options, args Arguments) (*Component, error) {
	c := &Component{opts: o}

	// Call to Update() to set the output once at the start
	if err := c.Update(args); err != nil {
		return nil, err
	}

	return c, nil
}

// Run implements component.Component.
func (c *Component) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Update implements component.Component.
func (c *Component) Update(args component.Arguments) error {
	newArgs := args.(Arguments)

	c.mut.Lock()
	defer c.mut.Unlock()
	c.args = newArgs

	fmt.Println("Input value:", newArgs.InValue)

	c.opts.OnStateChange(Exports{
		OutVal: "out",
	})

	return nil
}
