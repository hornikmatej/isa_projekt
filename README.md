# ISA, projekt (Klient POP3 s podporou TLS)

- **Autor:** Matej Hornik (xhorni20@fit.vutbr.cz)
- **Datum:** 2021-10-15

## Popis programu
Klient POP3 s podporou TLS, ktorý na základe požiadavku od klienta stiahne emaily zo servera do zadaného priečinka alebo vymaže emaily na zadanom serveri pomocou POP3 protokolu. Klient taktiež dokáže komunikovať zo serverom cez šifrované spojenie pomocou TLS.

## Preklad programu:
- make          - prelozenie programu
- make clean    - zmazanie suborov z prekladu a binarky 
- make zip      - vytvorenie zip archivu

## Príklad spustenia programu
```
./popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>
```

## Zoznam odovzdaných súborov:
- Makefile
- README
- popcl.cpp
- manual.pdf
