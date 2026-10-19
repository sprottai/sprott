# Sprott hero demo, rendered with vhs (https://github.com/charmbracelet/vhs):
#
#     vhs demo/demo.tape
#
# Storyboard (three beats, ~25 s):
#   1. what's connected: the agent sees hosts + phantoms, no values
#   2. the phantom works through `sprott run`: real API response comes back
#   3. the same phantom outside `sprott run` is a worthless string: clean 401
#
# Record on a machine with a paired daemon, an unlocked vault, and a github
# connection. Adjust sleeps to the real latency you see.

Output demo/demo.gif

Set FontSize 20
Set Width 1100
Set Height 560
Set TypingSpeed 35ms
Set Theme "Catppuccin Mocha"
Set Padding 20

Type "sprott connection ls"
Enter
Sleep 3s

Type "# the agent writes the phantom, never the token"
Enter
Sleep 1s
Type "GITHUB_TOKEN=__sc__github__ sprott run -- gh api user -q .login"
Enter
Sleep 4s

Type "# outside sprott run, the phantom is a worthless string"
Enter
Sleep 1s
Type "GITHUB_TOKEN=__sc__github__ gh api user -q .login"
Enter
Sleep 3s

Sleep 2s
