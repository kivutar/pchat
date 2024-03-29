package main

import (
	"fmt"
	"log"

	"github.com/jroimartin/gocui"
)

func draw() {
	// Create a new GUI.
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		panic(err)
	}
	defer g.Close()
	g.Cursor = true

	// Update the views when terminal changes size.
	g.SetManagerFunc(func(g *gocui.Gui) error {
		termwidth, termheight := g.Size()
		_, err := g.SetView("output", 0, 0, termwidth-1, termheight-4)
		if err != nil {
			return err
		}
		_, err = g.SetView("input", 0, termheight-3, termwidth-1, termheight-1)
		if err != nil {
			return err
		}
		return nil
	})

	// Terminal width and height.
	termwidth, termheight := g.Size()

	// Output.
	ov, err := g.SetView("output", 0, 0, termwidth-1, termheight-4)
	if err != nil && err != gocui.ErrUnknownView {
		log.Println("Failed to create output view:", err)
		return
	}
	ov.Title = "Messages"
	ov.Autoscroll = true
	ov.Wrap = true

	// Input.
	iv, err := g.SetView("input", 0, termheight-3, termwidth-1, termheight-1)
	if err != nil && err != gocui.ErrUnknownView {
		log.Println("Failed to create input view:", err)
		return
	}
	iv.Title = "New Message"
	iv.FgColor = gocui.ColorWhite
	iv.Editable = true
	err = iv.SetCursor(0, 0)
	if err != nil {
		log.Println("Failed to set cursor:", err)
		return
	}

	// Bind Ctrl-C so the user can quit.
	err = g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		return gocui.ErrQuit
	})
	if err != nil {
		log.Println("Could not set key binding:", err)
		return
	}

	// Bind enter key to input to send new messages.
	err = g.SetKeybinding("input", gocui.KeyEnter, gocui.ModNone, func(g *gocui.Gui, iv *gocui.View) error {
		// Read buffer from the beginning.
		iv.Rewind()

		// Send message if text was entered.
		if len(iv.Buffer()) >= 2 {
			err := send(iv.Buffer())
			if err != nil {
				fmt.Fprint(ov, "error: "+err.Error()+"\n")
			} else {
				fmt.Fprint(ov, "you: "+iv.Buffer())
			}

			// Reset input.
			iv.Clear()

			// Reset cursor.
			err = iv.SetCursor(0, 0)
			if err != nil {
				log.Println("Failed to set cursor:", err)
			}
			return err
		}
		return nil
	})
	if err != nil {
		log.Println("Cannot bind the enter key:", err)
	}

	// Set the focus to input.
	_, err = g.SetCurrentView("input")
	if err != nil {
		log.Println("Cannot set focus to input view:", err)
	}

	go func() {
		for msg := range messages {
			fmt.Fprint(ov, contact+": "+msg)
			g.Update(func(g *gocui.Gui) error {
				return nil
			})
		}
	}()

	// Start the main loop.
	err = g.MainLoop()
	log.Println("Main loop has finished:", err)
}
