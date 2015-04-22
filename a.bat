call kramdown-rfc2629 draft-schaad-cose.md > draft-schaad-cose.xml
call rake verify

c:\python34\python.exe c:\python34\scripts\xml2rfc draft-schaad-cose.xml -o cose.txt --text
c:\python34\python.exe c:\python34\scripts\xml2rfc draft-schaad-cose.xml -o cose.html --html
c:\python34\python.exe c:\python34\scripts\xml2rfc draft-schaad-cose.xml -o cose.exp --exp