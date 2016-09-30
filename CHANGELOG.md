# v1.2.0
Simplified the send_text and recv_text by moving the error handling to the end of Receiver#receive, and removing redundent statements. Removed the code which handled those errors (SLAM and TIMEOUT) from the Patterns list, and removed the associated handler code.

Fixed the accept logic to accept the email if one or more RCPT TO commands were valid (as opposed to requiring all to be valid).

Added an SPF check for the MAIL FROM address. To learn more about SPF, go to `http://www.openspf.org/`. The SPF check result goes to `@mail[:mailfrom][:spf]`.

# v1.1.0
Changed the defaults for :sender_mx_check and recipient_mx_check to true because the cost is low and we need to know if the sender has a mail server (remote-->local), or if the recipient has a mail server (local-->remote). You can still turn off these checks, if you don't want them.

In `psych_value`, added a test for "MAIL FROM: <>" (a bounce message). In the case this address is detected, the special value "<>" is passed back from psych_value in :url, and no :domain is created. (In other words, test for `:url=>"<>"` first.)

````ruby
  :mailfrom=>{
    :value=>"<>",
    :name=>"",
    :url=>"<>"
  },
````

# v1.0.0
This is the initial load of the gem. If you find a problem, report it to me at mjwelchphd@gmail.com, or FORK the library, fix the bug, then add a Pull Request.
