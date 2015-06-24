c:\tools\python27\python.exe c:\tools\python27\scripts\xml2rfc draft-schaad-cose-msg.xml -o cose.txt --text
c:\tools\python27\python.exe c:\tools\python27\scripts\xml2rfc draft-schaad-cose-msg.xml -o cose.html --html
c:\tools\python27\python.exe c:\tools\python27\scripts\xml2rfc draft-schaad-cose-msg.xml -o cose.xml --exp

call rake verify
