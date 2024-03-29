# Tema 1 PCOM - Dataplane Router
Made by Andrei Maruntis 323CA

## Task-uri implementate

Task-urile pe care le-am implementat sunt:

- Procesul de dirijare (30p)
- Protocolul ICMP (21p)

De asemenea am implementat partial Protocolul ARP, mai precis router-ul va raspunde la cereri de tip ARP request cu un ARP reply corespunzator, si am incercat sa implementez Longest Prefix Match eficient.

## Functionarea router-ului

La pornire, router-ul va citi din fisierele corespunzatoare tabela de rutare, respectiv tabela ARP. Dupa aceea, un pas important este acela de a filtra si de a sorta tabela de rutare, pentru a functiona **Longest Prefix Match eficient**.

### Longest Prefix Match eficient

Implementarea eficienta consta intr-o cautare binara. Pentru ca aceasta sa functioneze, am nevoie sa sortez tabela de rutare (eu am sortat descrescator) si sa filtrez anumite intrari pe care nu se poate face niciodata match. Aceste intrari pe care le elimin din tabela de rutare sunt intrari pentru care prefixul are mai multi biti nenuli decat masca. Este important sa le elimin, deoarece in acest fel prefixele din tabela de rutare vor fi in ordine descrescatoare. Pentru a intelege mai bine, sa ne uitam la urmatoarea situatie:

Vreau sa caut adresa ip 192.168.3.0 in tabela de rutare, in care am urmatoarele 3 intrari consecutive (obtinute in urma sortarii):
   
| Prefix      | Next hop | Masca           | Interfata |
|-------------|----------|-----------------|-----------|
| 192.168.3.0 | x.x.x.x  | 255.255.255.0   | x         |
| 192.168.3.0 | x.x.x.x  | 255.255.254.0   | x         |
| 192.168.2.0 | x.x.x.x  | 255.255.254.0   | x         |

Este posibil ca atunci cand efectuez cautarea binara sa dau match pe intrarea cu prefixul 192.168.2.0, care nu este intrarea corecta, deoarece prima intrare din tabel are prefixul cel mai mare si se potriveste cu ip-ul cautat. Pentru a ma asigura ca intrarea aleasa este totusi cea corecta, dupa ce termin cautarea binara (aka gasesc o adresa ip care a dat match), fac o cautare liniara cativa pasi in sus in tabela, pana cand se termina adresele ip pe care pot da match. In cazul de mai sus, ip-ul cautat nu ar da match pe intrarea a doua, deoarece masca este mai scurta decat adresa ip, iar cautarea sa ve opri pe intrarea gresita. Daca aplic filtrarea explicata mai sus, nu voi mai avea intrarea 2, iar cautarea va functiona corect.

Astfel, daca aplic cautarea binara, complexitatea cautarii in tabela de rutare va fi `O(log n + k)`, unde `k << n` (n = dimensiunea tabelei de rutare, k = nr de cautari liniare in susul tabelei dupa ce gasesc intrarea corecta). Mai mult, daca aplic filtrarea inainte sa sortez tabela, voi elimina cateva intrari din tabela si sortarea va fi mai rapida (pasul de sortare fiind necesar si la cautarea liniara).

### Procesul de dirijare

Pentru a dirija pachetele, router-ul se uita pe rand la toate campurile din header-ele acestuia, urmand pasii explicati si in enuntul temei: Verifica tipul de pachet (IP sau ARP), verifica mac-ul destinatie (daca nu este mac-ul sau il arunca), verifica IP-ul destinatie si incearca sa trimita pachetul mai departe etc. Pe masura ce face aceste prelucrari, modifica si campuri precum ttl, checksum.

### Protocolul ICMP

Daca router-ul primeste un pachet destinat IP-ului sau, va verifica daca acel pachet este de tip ICMP Echo request. Daca este, va modifica pachetul asa incat sa se potriveasca unui Echo reply (va modifica codul si tipul pachetului, va inversa adresele IP sursa si destinatie din header-ul ICMP) si il va trimite inapoi catre cine l-a cerut.

In cazul in care router-ul primeste un pachet cu `ttl <= 0` sau pentru care nu gaseste nicio intrare in tabela de rutare, router-ul va construi de la 0 un pachet nou care va contine:

- un header ethernet
- un header IP
- un header ICMP
- header-ul IP al pachetului care trebuie aruncat si inc a8 octeti din acesta

Toate campurile acestor headere vor fi completate corespunzator.

### Protocolul ARP

Singura functionalitate ARP pe care o are implementata router-ul este aceea de a raspunde la pachete de tip ARP request. Daca router-ul primeste un pachet ARP si acest pachet ARP este de tip ARP request, va raspunde cu un pachet ARP reply corespunzator.

## Alte observatii

Solutia mea contine multe printf-uri de debug foarte utile pentru a vedea usor ce face router-ul in timpul functionarii. Sper ca nu voi fi depunctat pentru acestea, motivatia pentru care le-am lasat este ca checker-ul nu merge cat de bine mi-as dori si inclusiv proful de curs (Florin Pop) a spus ca facem temele ca sa functioneze si nu pentru checker. Astfel, in cazul in care ar fi nevoie de verificare manuala la aceasta tema, va fi mult mai usor de facut.

Un alt lucru pe care doresc sa il spun este ca enuntul acestei teme ar putea fi imbunatatit in multe feluri. Pe langa anumite greseli de ortografie care ar putea indica o lipsa de profesionalism, in multe sectiuni ar fi utile explicatii suplimentare. Spre exemplu, eu am avut cele mai mari probleme la partea de ICMP, deoarece continutul multor campuri nu era specificat in enuntul temei, mai exact campurile IP: atunci cand trimit un raspuns ICMP de tip ttl exceeded sau host unreachable, trebuie sa setez campul protocol cu o anumita valoare care nu este specificata in enunt, iar in fisierul librarie scrie "don't care", insa protocolul nu va functiona corespunzator fara valoarea corecta in acel camp.

Nu in ultimul rand, tema este extrem de dificila. Indiferent de motive, mi se pare ca anumite functionalitati, precum LPM eficient si protocolul ARP, sunt functionalitati foarte avansate si dificil de implementat (mai ales protocolul ARP), dar in acelasi timp ruterul va functiona si fara ele. Cred ca ar fi mai bine ca aceste task-uri sa devina task-uri bonus pentru a face tema mai accesibila.
