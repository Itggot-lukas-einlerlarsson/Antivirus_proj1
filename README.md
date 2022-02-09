# Antivirus_proj
A simple antivirus program i did early last year(jan, 2021), one of my first projects i did in C++. 

The program first traverses a given directory.
It then reads the signatures in the .db file,
the signatures in the .db file is in hexadecimal form. 
The program then reads a small portion of each file(top of file), converts the strings of each file read into hexadecimalform 
and then checks if the signatures match any of those in the database

ex: test.pdf file:
%PDF-1.5
%ÐÔÅØ
3 0 obj
<<
/Leng

Becomes in hex:

255044462d312e350a25d0d4c5d80a332030206f626a0a3c3c0a2f4c656e67

To run on linux:
go to directory you have the program files
use "make all", 
then write: "make run" or "./a.out directory_you_choose"
