package rdp

import (
	"fmt"
	"testing"
	"time"
)

func TestRdp(t *testing.T) {
	c := NewClient("127.0.0.1:3389",
		time.Second*3,
		WithScreenshot(Picture{}),
		WithAuth("administrator", "132565"),
	)
	if !c.IsXRdp() {
		fmt.Println(c.GetBanner())
		c.Login()
	}

}
