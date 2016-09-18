 
   THIS IS AN LSE SYSTEMS PROGRAMMING TEST AIMED FOR A FACE TO FACE INTERVIEW WHEN
   ALL FAULT DIAGNOSIS TESTS HAVE BEEN DONE REMOTELY

   It took me ~30 minutes to craft this in C and for it to be bug-free.
   It took me ~15 minutes to craft this in python.

   I would offer 60 - 90 minutes for someone to accomplish this (if we dont template).

   Test demonstrates the following skills:
     The candidate understands how to use signals.
     The candidate can parse a simple output grammar.
     The candidate can do file io programatically.
     Candidate understands results of ERRNO and that EINTR is not necessarily an error.

   The process will be that you show ftsewatch running in the console to they can see
   the output.
   You then show them ftsereport which almost does the correct thing but has a bug
   (totals dont match ups/downs most iterations.)
   ·Inform candidate can use any language.
   ·Inform candidate that ftsewatch is intolerant of delays.
   ·Inform candidate that ftsewatch always sends 65536 bytes to the pipe
     (this fills up the pipe and causes writes to block for ftsewatch).
   ·Inform candidate that ftsewatch company name character sets are:
     "a-z", "A-Z", "0-9", "&", "_", "-", " "

   Things to look for;

   An algorithm that calls alarm(5) inside of the SIGALRM handler
   is OK instead of using setitimer. Just not as elegant.

   Not ideal, but acceptable if candidate just checks the end of the string for UP/DOWN.


 DESCRIPTION
 ftsewatch is a program that monitors the ftse100 stocks and reports an event if the stock 
 just went UP in value or DOWN in value.

 OBJECTIVE 
 Write a peice of software which will read from the ftsewatch program
 · The program should count all the UPS and DOWNS that appear over a five second interval.

 · At the five second interval, produce a total count of all UPS, all DOWNS and the total
   received messages from the program.

 · Once the program has generated the report, reset the count of UPS, DOWNS and TOTAL to 0.

 · If the program receives a SIGHUP, it should print the report immediately.

 · If a SIGHUP was received, its OK if the program produces a partial report for its interval 
   report.
 
 THINGS TO KNOW:
 · You can use any programming language you feel will help you accomplish this task.

 · ftsewatch is intolerant of delay. It will promptly time out and exit if it detects
   that the pipe is blocked!

 . ftsewatch always sends a message which is always 65536 bytes in size. You must consume
   all the buffer promptly to allow ftsewatch to send the next message.

 · All company name characters are contained in the character set:
   a-z, "A-Z", "0-9", "&", "_", "-", " "

 · There is an example program that does this task: "ftsereport". You can run "ftsewatch | ftsereport"
   to get a feel for what is trying to be acheived. Note ftsereport has a bug; Often the total ups/downs
   do not match the total it has supposedly received.

