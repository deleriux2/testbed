def runwait(timeout, *args):
  from os import fork, execvp, waitpid, kill, dup2
  from signal import alarm, signal, SIGTERM, SIGALRM, SIG_DFL
  from errno import EINTR

  ## We dont do much in the alarm handler, we only care that we interrupted
  ## the wait() on the process.
  def onalarm(sig, frame):
    pass

  ## This is used for redirecting stdin/out/err to /dev/null
  devnull = open('/dev/null', 'r+')
  pid = fork()
  if not pid:
    ## The child process. Begin by redirecting all input and output.
    dup2(devnull.fileno(), 0)
    dup2(devnull.fileno(), 1)
    dup2(devnull.fileno(), 2)
    ## Probably not a great idea to pass this file descriptor to whatever we 
    ## end up executing.
    devnull.close()

    ## Overwrite child process with new execution context.
    execvp(args[0], args)
    ## If something failed (like command not found) exit 63. WARNING, because we
    ## redirected all output to /dev/null, you WILL NOT be informed the command was
    ## not found directly. Use the exit code to work that out.
    sys.exit(63)

  ## This is the parent process that initiated the fork.
  ## Arm a timer using timeout given by first parameter of function. This
  ## must be an int, not a float. I dont bother checking though cause I'm lazy.    
  signal(SIGALRM, onalarm)
  alarm(timeout)

  ## We wait on the pid, this call typically blocks forever.
  try:
    pid, rc = waitpid(pid, 0)
  except OSError as e:
    ## We will land here if the alarm triggered BEFORE the process completed!
    ## In this case, if we were interrupted to deal with the 
    ## signal handler its definitely an alarm. Otherwise
    ## a peripheral exception occurred (permissions for example) so just re-raise the exception.
    if e.errno == EINTR:
      ## We send a TERM signal to terminate the process and re-wait. This causes
      ## wait to (under normal conditions) come back immediately with the signal 
      ## we just killed it with which parse out further down.
      kill(pid, SIGTERM)
      pid, rc = waitpid(pid, 0)
    else:
      raise

  ## Waits status is a 16bit integer packing a 8bit signal and 8bit return code.
  ## Do some funky bitwise operations to separate the two..
  sig = rc & 0xff
  rc >>= 8
  ## Whatever happened above, always disable the alarm and signal handling.
  alarm(0)
  signal(SIGALRM, SIG_DFL)
  return sig, rc


if __name__ == "__main__":
  # An example when you time out
  print runwait(2, "sleep", "20")
  # An example on success
  print runwait(5, "sleep", "3")
  # More success, but demonstrating no output
  print runwait(5, "grep", "root", "/etc/passwd")
