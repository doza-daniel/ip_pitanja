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

## Sta je slicnost/razlicitost objekata/obrazaca/atributa?
Slicnost i razlicitost izmedju objekata su funkcije koje nam govore o tome koliko su dva objekta
slicna ili razlicita. Vece vrednosti funkcije slicnosti nam govore da su objekti vise slicni, a
obrnuto vazi za funkcije razlicitosti.  Uglavnom se funkcije slicnosti mere u vrednostima na
intervalu [0, 1], dok se funkcije razlicitosti mere na intervalu od 0 (objekti su isti) na vise.
Koriste se i termini rastojanje (distance), blizina (proximity).

Funkcije slicnosti i razlicitosti su od velikog znacaja, jer imaju uticaj na svaki problem u
istrazivanju podataka. Los izbor funkcije slicnosti moze da ima presudnu vrednost u tome da li
smo odradili dobar posao. Ova cinjenica nam govori da ne smemo zapostaviti izbor funkcije
slicnosti i samo se fokusirati na algoritamski deo problema istrazivanja podataka.

## Navesti primer funkcije slicnosti/razlicitosti za nominalne atribute *p* i *q*.

#### Slicnost
* *sim(p, q) = 1 <=> p = q*
* *sim(p, q) = 0 <=> p =/= q*

#### Razlicitost
* *dist(p, q) = 0 <=> p = q*
* *dist(p, q) = 1 <=> p =/= q*

## Navesti primer funkcije slicnosti/razlicitosti za redne atribute *p* i *q*.
Ako *p* i *q* mogu imati *n* razlicitih vrednosti, onda funkcije slicnosti i razlicitosti
definisemo na sledeci nacin:

#### Slicnost
* *sim(p, q) = 1 - |p - q| / (n - 1)*

#### Razlicitost
* *|p - q| / (n - 1)*

## Navesti primer funkcije slicnosti/razlicitosti za intervalne i razmerne atribute *p* i *q*.

#### Slicnost
* *sim(p, q) = -dist(p, q)*
* *sim(p, q) = 1/ (1 + dist(p, q))*

#### Razlicitost
* *dist(p, q) = |p - q|*

## Sta treba da vazi za funkciju rastojanja *d* da bi ona bila metrika?
Da bi funkcija rastojanja *d* je metrika ako i samo ako vazi:
1. Pozitivna odredjenost:
  * *d(p, q) >= 0* za svako *p* i *q* 
  * *d(p, q) = 0 <=> p = q*
1. Simetrija
  * *d(p, q) = d(q, p)* za svako *p* i *q*
1. Nejednakost trougla
  * *d(p, q) <= d(p, z) + d(z, q)* za svako *p*,*q* i *z*

## Sta treba da vazi za funkciju rastojanja *d* da bi ona bila ultrametrika?
Funkcija *d* je *ultrametrika* ako je metrika i ako vazi:
* *d(p, q) <= max{d(p, z), d(z, q)}* za svako *p*,*q* i *z*

## Koje se mere rastojanja cesto koriste za kvantitativne podatke?
Hamingovo rastojanje, rastojanje Minkovskog, Mahalanobisovo rastojanje.

## Sta je rastojanje Minkovskog (prednosti/nedostaci)?
Za dva objekta *X=(x1,x2,...,xn)* i *Y=(y1,y2,...,yn)* Rastojanje minkovskog se definise kao:
* *(sum\[i = 1 to n\] -> |xi - yi|^p)^(1 / p)*

Rastojanje Minkovskog za *p = 2* je Euklidsko rastojanje, za *p = 1* je Menhetn rastojanje.
Prednost ove metode je u tome sto je veoma intuitivna. Medjutim, to sto je intuitivna, ne znaci
da daje dobre rezultate, pogotovo u slucajevima velike dimenzionalnosti. Na primer ne uzima u
obzir koliko je neki atribut bitan za odredjivanje slicnosti. Takodje lose radi ako je nepoznata
raspodela...


## Sta je Mahalanobisovo rastojanje (prednosti/nedostaci)?
Jedan od nedostataka rastojanaj Minkovskog je sto zavisi samo od objekata nad kojim se formula
izracunava, a ne obraca paznju na distribuciju ostalih podataka. Mahalanobisovo rastojanje
uzima u obzir raspodelu podataka koristeci matricu kovarijansi. Neka su *X=(x1,x2,...,xn)* i
*Y=(y1,y2,...,yn)* dva objekta. Mahalanobisovo rastojanje izmedju *X* i *Y* je:

* *Maha(X, Y) = sqrt((X - Y)  E^(-1)  (X - Y)^T)*

Drugim recima uzimamo razliku vektora *X* i *Y* pomnozimo sa inverzom matrice kovarijani *E* i
transponovanom razlikom vektora *X* i *Y*.

## Kako se moze definisati slicnost podataka sa kategorickim atributima?
Kad radimo sa kategorickim funkcijama obicno se vise koriste funkcije slicnosti nego
razlicitosti jer je se diskretne vrednosti mogu prirodnije porediti.  Slicnost podataka sa
kategorickim atributima se moze definisati preko slicnosti njihovih pojedinacnih atributa. Neka
su *X=(x1,x2,...,xn)* i *Y=(y1,y2,...,yn)* objekti. Njihovu slicnost mozemo definisati kao:
* *Sim(X, Y) = sum\[i = 1 to n\] S(xi, yi)*

Odavde vidimo da izbor funkcije *S* odredjuje citavu funkciju slicnosti. U najjednostavnijem
slucaju funkcija *S* se moze definisati kao 
* *S(x_i, y_i) = 1 <=> x_i = y_i*
* *S(x_i, y_i) = 0 <=> x_i =/= y_i*

Medjutim, mozemo uvideti da je problem kod ove funkcije da ona ne uzima u obzir frekvenciju
razlicitih atributa. Uzmimo na primer atribut koji moze da ima vrednosti 'Normalno', 'Rak' i
'Dijabetes'. Najverovatnije je da ce 99% podataka imati vrednost 'Normalno' ali oni nece biti
od statisticke vaznosti isto toliko koliko i objekti sa vrednostima 'Rak' i 'Dijabetes'. Drugim
recima, velika vecina nam ne odredjuje dovoljno dobro slicnost izmedju objekata. Sa ovim na umu
treba kreirati nesto slicno Mahalanobisovom pristupu.

Pristup koji koristimo naziva se *inverzna frekvencija ponavljanja*. Neka je *p_i(x)* broj
slogova ciji *i*-ti atribut ima vrednost *x*. Tada mozemo nasu funkciju *S* definisati kao
* *S(x_i, y_i) = 1 / p_i(x_i)^2 <=> x_i = y_i*
* *S(x_i, y_i) = 0 <=> x_i =/= y_i*

## Kako se odredjuje slicnost tekstualnih dokumenata?
Tekstualne dokumente mozemo smatrati multidimenzionim podacima kada bi ih posmatrali kao 'vrece
reci'. To bi znacilo da bi kompletan set atributa nekog dokumenta bio ceo leksikon reci, a
vrednosti bi bile broj pojavljivanja odgovarajuce reci u dokumentu. Ovakav format bi znacio da
ce vecina atributa imati vrednost 0, sto bi dalje povlacilo da kada bismo koristili nesto kao
sto je rastojanje Minkovskog, dva slicna dugacka teksta ce uvek biti vise razlicita nego dva
zapravo razlicita kraca teksta. Da bismo ovo izbegli, koristimo kosinusno rastojanje. Neka su
*X=(x1,x2,...,xn)* i *Y=(y1,y2,...,yn)* dva objekta. Kosinusno rastojanje definisemo kao:
* cos(X, Y) = sum\[i = 1 to n\] xi * yi / (sqrt(sum\[i = 1 to n\](xi^2)) * sqrt(sum\[i = 1 to n
\](yi^2)))

## Sta je rastojanje Minkovskog sa tezinama?
U nekim slucajevima, nisu svi atributi objekta podjednako bitni u odredjivanju slicnosti. Na
primer, visina plate igra mnogo vecu ulogu nego pol u slucaju odobravanja kredita. U ovakvom
slucaju mozemo koristiti rastojanje Minkovskog sa tezinama (generalizovano rastojanje
Minkovskog).
* (sum\[i = 1 to n\] -> ai * |xi - yi|^p)^(1 / p)

Vrednost *ai* nam govori o vaznosti *i*-tog atributa u poredjenju dva objekta. Vrednosti *ai*
se dobijaju heuristickim metodama i u velikoj meri zavise od iskustva analiticara.

## Kako se odredjuje slicnost dva sloga sa kvantitativnim i kategorickim atributima?
## Sta je SMC (simple matching coefficient)?
## Sta su Zakardovi koeficijenti? Kada se koriste?
## Sta su prosireni Zakardovi koeficijenti (koeficijenti Tanimoto-a)?
## Kako se definise kosinusna slicnost dva objekta? Kada se koristi?
## Sta je korelacija dva objekta?
## Sta su mere na osnovu gustina?
## Kako izrazavamo slicnost diskretnih podataka?
## Sta je entropija?
## Sta su mere slicnosti zasnovane na teoriji informacija?
## Sta su mere na osnovu gustina? Koje se metode najcesce koriste?
