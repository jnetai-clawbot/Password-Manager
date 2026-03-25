#!/bin/bash
cd /home/jay/Documents/Scripts/AI/openclaw/job17/C/gui
rm -f passwords.db

# Start Xvfb
Xvfb :97 -screen 0 1024x768x24 > /dev/null 2>&1 &
XVFB_PID=$!
export DISPLAY=:97
sleep 2

# Run GUI with debug output captured
./password_manager_gui 2>/tmp/gui_debug.log &
GUI_PID=$!
sleep 3

echo "=== GUI started with PID $GUI_PID ==="
echo "Checking if running..."
if kill -0 $GUI_PID 2>/dev/null; then
    echo "GUI is running"
else
    echo "GUI is NOT running (crashed)"
    cat /tmp/gui_debug.log
    kill $XVFB_PID 2>/dev/null
    exit 1
fi

# Try to find and focus the window
WID=$(xdotool search --name "Password Manager" 2>/dev/null | head -1)
if [ -n "$WID" ]; then
    echo "Window found: $WID"
    xdotool windowfocus $WID
    sleep 1
    
    # Tab to first password field, type password
    xdotool type "testmasterpass" 2>/dev/null
    sleep 0.5
    xdotool key Tab 2>/dev/null
    sleep 0.5
    xdotool type "testmasterpass" 2>/dev/null
    sleep 0.5
    xdotool key Return 2>/dev/null
    sleep 3
    
    echo "=== After setup attempt ==="
    if kill -0 $GUI_PID 2>/dev/null; then
        echo "GUI still running after setup"
        cat /tmp/gui_debug.log | tail -30
    else
        echo "GUI crashed after setup"
        cat /tmp/gui_debug.log
    fi
    
    # Now try clicking Add Entry
    WID=$(xdotool search --name "Password Manager" 2>/dev/null | head -1)
    if [ -n "$WID" ]; then
        xdotool windowfocus $WID
        sleep 0.5
        # Try pressing Tab to navigate to Add Entry button
        xdotool key Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Tab Return 2>/dev/null
        sleep 2
        
        # Now type site, username, password
        xdotool type "github.com" 2>/dev/null
        xdotool key Tab 2>/dev/null
        sleep 0.3
        xdotool type "testuser" 2>/dev/null
        xdotool key Tab 2>/dev/null
        sleep 0.3
        xdotool type "secretpass123" 2>/dev/null
        xdotool key Tab Tab Return 2>/dev/null
        sleep 3
        
        echo "=== After add entry attempt ==="
        if kill -0 $GUI_PID 2>/dev/null; then
            echo "GUI still running after add entry"
        else
            echo "GUI crashed after add entry"
        fi
        cat /tmp/gui_debug.log
    fi
else
    echo "No window found"
    cat /tmp/gui_debug.log
fi

kill $GUI_PID $XVFB_PID 2>/dev/null
wait 2>/dev/null
