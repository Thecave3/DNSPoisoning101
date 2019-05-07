run_listener:
    xterm -e 'python listener.py'

run_venom:
	xterm -e 'python venom.py'

all:
	run_listener 
	run_venom