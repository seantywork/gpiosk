savedcmd_/home/seantywork/hack/gpiosk/gpiosk.mod := printf '%s\n'   gpiosk.o | awk '!x[$$0]++ { print("/home/seantywork/hack/gpiosk/"$$0) }' > /home/seantywork/hack/gpiosk/gpiosk.mod
