package rdp

import (
	"fmt"
	"testing"
	"time"
)

func TestRdp(t *testing.T) {
	c := NewClient("10.189.62.191:3389",
		time.Second*3,
		WithScreenshot(Picture{}),
		WithAuth("administrator", "132565"),
	)
	if !c.IsXRdp() {
		fmt.Println(c.GetBanner())
		c.Login()
	}

}
