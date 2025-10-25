### Disclaimer: 
This is my first time working on a full cpp project , so it's a little messy, there is open-fhe python library but was not sure about the full availability of the api so went ahead with cpp.


### Software Design: 

/harness: contains the primary logic for the code 
main.cpp -> orchestrates everything
./data_synthesis.py -> generates data 1000x 512D unit-normalized vectors
and a query vector -> 512 D it is encrypted and unit-nomralized during the run to simulate real world use case
/users -> simulated users who will have different parts of the key and only the threshold max will be decrypted at the end.
openfhe -> built openfhe 1.42.0 for this project  , to dowload it with this project run 
git clone --recursive-submodule <repo-link>
### SETUP INSTRUCTIONS:
run the ./build_main.sh after editing the CMakeLists.txt for your path to the openfhe library, 

### CKKS Params:
CKKS params (
    ring dimension: , 
    modulus chain: , 
    scaling factor: ,
),

### My system specifications:
I am running it on :
OS: Macos
compiler: clang++
CPU: arm based M2 pro

### How to reproduce
I have used datasets from the /datasets folder running the simulation again on them should result in the same results

### One unified command
./main compare 1 0.85
1 -> dataset no
0.85 -> threshold

### Design Notes:
https://www.notion.so/Mercle-Assignment-Design-notes-29644d413d1a801cba3bf7229fb322f5?source=copy_link

### Results