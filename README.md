# Istrazivanje podataka
## Sta je istrazivanje podataka?

  Ne postoji precizna definicija istrazivanja podataka, ali se smatra da je to skup
algoritama i tehnika koji omogucava automatsko zakljucivanje nekih cinjenica i veza iz
velikog skupa podataka, koji bi mozda inace ostali neotkriveni.

## Koji su zadaci istrazivanja podataka?

Zadaci u istrazivanju podataka se mogu podeliti u dve grupe: zadaci opisivanja i
zadaci predvidjanja. Zadaci predvidjanja bave se odredjivanjem vrednosti nekog atributa
na osnovu vrednosti neki drugih atributa. Ove atribute nazivamo *zavisne promenljive*
ili *ciljne promenljive* a atribute na osnovu kojih dolazimo do zakljucaka
*opisne promenljive* ili *nezavisne promenljive*.
  1. **Klasifikacija** - pravimo funkciju od nezavisnih varijabli da bi dobili
  zavisne varijable
    * klasifikacija - za diskretne podatke, na primer: da li ce kupac kupiti neki artikal
    * regresija - za kontinualne podatke, na primer: koliko ce stepeni biti u neko vreme
  1. **Prepoznavanje obrazaca** - nalazimo veze u podacima: na primer ako je kupac kupio pelene,
  verovatno je da ce
    kupiti i mleko.
  1. **Klasterovanje** - grupisemo podatke prema slicnosti, na primer: grupisemo dokumente
  vezane za ekonomiju u jedan klaster, a dokumente vezane za medicinu u drugi klaster.
  1. **Otkrivanje anomalija** - otkrivanje podataka koji su veoma drugaciji od ostalih.
  Ove podatke nazivamo anomalije ili autlajeri


## Sta su podaci?

Skup podataka mozemo predstaviti kao skup *objekata*. Ovi objekti se takodje mogu nazivati
i *slog*, *slucaj*, *uzorak*, *vektor*... Objekte opisuju njihovi *atributi* koji nam govore
o osobinama tog objekta, na primer: boja, visina, tezina... Atributi se jos nazivaju i
*karakteristika*, *varijabla*, *polje*...

## Sta je atribut?

Atribut je karakteristika objekta. Atribut moze da varira izmedju razlicitih objekata ili
da varira u vremenu. Boja ociju je razlicita za dva coveka, a na primer, temperatura nekog
predmeta varira u toku vremena.

## Sta je vrednost atributa?

Vrednost atributa je broj ili simbol koji je pridruzen atributu. Moramo razlikovati vrednost
atributa od samog atributa, jer vrednosti mogu da imaju neke osobine koje atribut nema, i
obrnuto. Na primer ako za zaposlenog cuvamo identifikacioni broj i broj godina, ima smisla
racunati prosek godina, dok nema smisla racunati prosek identifikacionog broja. Jedina logicna
operacija sa identifikacionim brojevima je poredjenje jednakosti.

## Kako odredjujemo tip atributa?

Tip atributa mozemo odrediti na osnovu broja vrednosti koji moze da sadrzi:
  * **diskretni** (konacni, ili prebrojivo beskonacni skupovi vrednosti, primer: postanski
      brojevi)
  * **neprekidni** (realni brojevi, primer: temperatura, tezina, pritisak, brzina)

*Asimetricni atributi* - kod njih je bitna samo ne-nula vrednost. Na primer vrednost 1 ako je
student pohadjao kurs, a vrednost 0 ako nije. U tom slucaju bi nas zanimali samo studenti sa
vrednoscu 1.


Takodje, tip atributa mozemo posmatrati na osnovu operacija koje se mogu izvrsiti nad njihovim
vrednostima

| Vrsta Operacije | Rbr | Operacija | Tip Atributa |
|-----------------|-----|-----------|--------------|
| razlicitost | 1 | = i =/= | Imenski(1) |
| uredjenje | 2 | <, >, <=, >= | Redni(1,2) |
| aditivnost | 3 | +, - | Intervalni(1,2,3) |
| multiplikativnost | 4 | *, / | Razmerni(1,2,3,4) |

* **Kategoricki** - imenski i redni
* **Numericki** - intervalni i razmerni

## Koje su karakteristike skupa podataka?

1. dimenzionalnost - predstavlja broj atributa koje objekti imaju
1. retkost - uzmimo na primer asimetricne podatke, mozda razmatramo samo 1% od ukupnog broja
objekata
1. rezolucija - sa kojim nivoom detalja gledamo na podatke. na primer zemlja gledana sa par metara
je proprilicno neravna, a gledano sa par desetina kilometara je poprilicno glatka.

## Koji su tipovi skupa podataka?

Tipovi podataka nisu precizno definisani, ali ih mozemo grupisati u tri grube kategorije:
1. Slogovi
1. Grafovski podaci
1. Uredjeni podaci

## Sta su torke?

Podrazumeva da su podaci organizovani kao torke koje predstavljaju objekte. Svaki objekat ima
fiksan broj atributa. U svojoj osnovnoj formi, smatramo da ne postoje veze izmedju torki, kao ni
izmedju atributa, i svaki objekat ima isti skup atributa.

#### Transakcije
Transakcija je specijalan slucaj torki. Asocijacija se moze napraviti sa *potrosackom korpom*.
Svaka torka sadrzi skup elemenata koje je kupac kupio u jednoj kupovini.

#### Matrice podataka
Ukoliko svi objekti imaju isti broj atributa, podaci se mogu posmatrati kao matrica. Redovi ove
matrice predstavljaju objekte, a kolone predstavljaju atribute (obrnuto je takodje dozvoljeno).
U ovakvom uredjenju, objekte mozemo posmatrati kao *n*-dimenizione vektore, gde su dimenzije
odredjene atributima.

## Sta su grafovski podaci?

#### Grafovi sa vezama izmedju podataka u granama
Objekti su u ovom modeli predstavljeni kao cvorovi grafa, dok su veze izmedju objekata
prikazane granama. Kao primer mozemo uzeti Web stranice.

#### Objekti predstavljeni kao grafovi
Ako su objekti sacinjeni od podobjekata koji imaju medjusobne veze, takve objekte cesto
predstavljamo kao grafove. Kao primer mozemo uzeti hemijska jedinjenja, gde cvorovi
predstavljaju atome, a grane predstavljaju hemijske veze.

## Sa su uredjeni podaci?
Ponekad su podaci uredjeni na osnovu vremena i/ili prostora.

#### Vremenski podaci
Uredjeni su kao slogovi, s tim sto je svakom slogu pridruzeno vreme. Ovim mozemo odredjivati
na primer porast u kupovini slatkisa pred noc vestica.

#### Podaci u odredjenom redosledu
Slicni su vremenskim podacima, ali nemaju vremenske odrednice, vec su poredjani u uredjenom
rasporedu. Primer su genetske sekvence.

#### Serijski podaci
Vrlo slicni vremenskim podacima, samo sto svaki objekat cini serija podataka izmerenih u toku
nekog perioda.

#### Prostorni podaci
Objekti sadrze prostorne odrednice. Primer bi bio podaci o vremenskoj prognozi.

## Sta je prepoznavanje obrazaca?
Prepoznavanje obrazaca se moze, u osnovnoj formi predstaviti preko binarne matrice. Moze se
posmatrati takva matrica da kolone predstavljaju artikle, a redovi transakcije kupaca. Polje
*(i,j)* je 1 ako je kupac kupio artikal, inace je 0. Cilj nam je da prepoznamo da li postoje
neka pravila u kupovini, tojest, da li su vece sanse da kupac kupi stvar *x* ako je kupio stvar
*y*. Formalno: neka je data binarna matrica *n x d*, posmatramo podskupove kolona, takve da sve
imaju vrednost 1. Svakom tom podskupu se dodeljuje podrska *s*, koja predstavlja ucestalost
ponavljanja tog podskupa u odnosu na ceo skup. Ukoliko je *s* vece od minimalne podrske,
smatramo da je obrazac cest.

## Sta je podrska pravila pridruzivanja?
Neka su A i B dva skupa obrazaca. Podrska **sup(A=>B)** je definfinisana kao #(A *U* B) / N;
Gde #(A *U* B) predstavlja broj zadovoljavajucih obrazaca, a N ukupan broj redova u kompletnom skupu.

## Sta je pouzdanost pravila pridruzivanja?
Neka su A i B dva skupa obrazaca. Pouzdanost **conf(A=>B)** je definisana kao #(A *U* B) / #(A).

## Sta je klasterovanje? (gruba definicija)
Klasterovanje je grupisanje objekata na osnovu njihove 'slicnosti'. Uvidja se da je od velike
vaznosti dizajn funkcije 'slicnosti'.

## Sta je otkrivanje elemenata van granica? (gruba definicija)
Zadatak je otkriti element koji je u velikoj meri razlicit od svih ostalih. Ovaj element zovemo
anomalija ili autlajer. Mozemo autlajere posmatrati i kao 'element koji je toliko razlicit od
ostalih, da se moze posumnjati da je nastao nekim razlicitim mehanizmom'. Primeri bi bili upad
u racunarski sistem, zloupotreba kreditnih kartica...

## Sta je klasifikacija? (gruba definicija)
Klasifikacija je problem odredjivanja vrednosti nekog specijalnog atributa. Problem
klasifikacije je problem nadgledanog ucenja. Formiramo skup podataka koje nazivamo  podaci za
trening, na osnovu kojih nas algoritam odredjuje odnos ostalih atributa i specijalnog atributa
koji se trazi. Nakon toga test podaci se koriste da se utvrdi preciznost algoritma i eventualno
podese parametri u cilju povecanja preciznosti. Onda mozemo koristiti dobijen algoritam za
odredjivanje specijalnog atributa u skupovima podataka gde je on nepoznat.

## Navesti par primera istrazivanja podataka
1. rasporedjivanje artikala u prodavnici
1. prepouke kupcima
1. anomalije u logovima aplikacija
