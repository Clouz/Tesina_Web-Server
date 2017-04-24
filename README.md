# Web Server Java con Socket SSL
## L'importanza di una comunicazione sicura attraverso internet

1.	[ABSTRACT](#ABSTRACT)
1.	[LA CRITTOGRAFIA](#LA_CRITTOGRAFIA)
	1.	[CRITTOGRAFIA SIMMETRICA](#CRITTOGRAFIA_SIMMETRICA)
	1.	[CRITTOGRAFIA ASIMMETRICA](#CRITTOGRAFIA_ASIMMETRICA)
	1.	[L’ARGORITMO RSA](#ARGORITMO_RSA)
	1.	[IL PROTOCOLLO SSL/TLS](#PROTOCOLLO_TLS)
1.	[JAVA: CHIAVI, CERTIFICATI E SOCKET SSL](#JAVA_CHIAVI_CERTIFICATI_SOCKET_SSL)
	1.	[GESTIRE CHIAVI E CERTIFICATI IN JAVA (KEYTOOL)](#KEYTOOL)
	1.	[L’USO DEI SOCKET SSL/TLS IN JAVA](#SOCKET_TLS_IN_JAVA)
1.	[UN SEMPLICE WEB SERVER HTTPS IN JAVA](#WEB_SERVER_HTTPS_IN_JAVA)
	1.	[INTRODUZIONE](#INTRODUZIONE)
	1.	[CICLO DI VITA DEL WEB SERVER](#CICLO_VITA_DEL_WEB_SERVER)
	1.	[CREAZIONE DEL SERVER SOCKET](#CREAZIONE_DEL_SERVER_SOCKET)
	1.	[ATTESA DEL CLIENT](#ATTESA_DEL_CLIENT)
	1.	[HTTP REQUEST](#HTTP_REQUEST)
	1.	[HTTP RESPONSE](#HTTP_RESPONSE)
	1.	[IL COMPORTAMENTO DI UN BROWSER INTERROGANDO IL WEB SERVER](#INTERROGANDO_IL_WEB_SERVER)
1.	[ANALISI DEI PACCHETTI CON WIRESHARK](#ANALISI_DEI_PACCHETTI_CON_WIRESHARK)
	1.	[INTRODUZIONE](#INTRODUZIONE)
	1.	[HTTP SNIFFING CON WIRESHARK](#HTTP_SNIFFING_CON_WIRESHARK)
	1.	[HTTPS SNIFFING CON WIRESHARK](#HTTPS_SNIFFING_CON_WIRESHARK)
1.	[CONCLUSIONI](#CONCLUSIONI)
1.	[RIFERIMENTI](#RIFERIMENTI)
	
## ABSTRACT <a name="ABSTRACT"></a>
Con questa tesina ho voluto approfondire un argomento che ha saputo incuriosirmi particolarmente: la crittografia e l’importanza che assume ai giorni nostri. Per fare questo ho sviluppato un mio progetto per potermi imbattere nelle problematiche realizzative e verificarne con mano l’effettivo funzionamento.
Partendo dalle conoscenze maturate durante l’anno scolastico sui Socket TCP in Java, sulla crittografia simmetrica e asimmetrica e sul protocollo HTTP (Hypertext Transfer Protocol), ho voluto sviluppare un semplice Web Server utilizzando i socket. Esso è in grado di gestire le richieste di trasferimento di pagine web provenienti da un web browser. 
Ho iniziato lo sviluppo implementando le funzioni di base del protocollo HTTP, interpretando le richieste provenienti dal browser (HTTP Request) ed impacchettando le risposte (HTTP Response). Successivamente ho approfondito le mie conoscenze sui Socket SSL in Java implementandoli nel mio web server. In questo modo la mia comunicazione tramite il protocollo HTTP avviene all’interno di una connessione criptata TLS (Transport Layer Security) così diventando a tutti gli effetti il protocollo HTTPS (HTTP over TLS). 
Il protocollo HTTPS comporta molti vantaggi dal punto di vista della sicurezza. Assicura che la comunicazione tra l’utente ed il sito web non sia né intercettata né alterata da terzi e dà una garanzia soddisfacente che si stia comunicando esattamente con il sito web voluto. Per fare ciò è necessario, oltre ai due interlocutori, anche di una terza parte fidata, una Certification Authority (CA), per la creazione del certificato digitale. In questo progetto, non avendo a disposizione una CA, ho dovuto provvedere a creare un mio certificato self-signed; in questo modo ho potuto anche constatare i comportamenti dei browsers in presenza di un certificato non riconosciuto da una CA.
Per finire ho messo alla prova il web server confrontando la versione HTTP con quella HTTPS, utilizzando il software Open Source Wireshark, il quale permette di osservare in tempo reale tutto il traffico presente sulla rete. Ho verificato che i pacchetti provenienti dal mio web server HTTP fossero trasmessi in chiaro e visibili da chiunque fosse riuscito ad intercettare la comunicazione, mentre nella versione HTTPS la comunicazione viene cifrata, impedendo a qualsiasi malintenzionato di visionare quanto trasmesso e/o alterarlo.
Da questa esperienza ho potuto constatare con mano quanto sia importante una comunicazione sicura, soprattutto oggigiorno con l’enormità di dati sensibili che viaggiano su internet, come ad esempio quelli scambiati durante gli acquisti online.

##	LA CRITTOGRAFIA <a name="LA_CRITTOGRAFIA"></a>
###	CRITTOGRAFIA SIMMETRICA <a name="CRITTOGRAFIA_SIMMETRICA"></a>
La crittografia simmetrica rappresenta un metodo semplice per cifrare testo in chiaro dove la chiave per cifrare è la stessa per decifrare, rendendo l'algoritmo molto performante e semplice da implementare.
Uno dei primi sistemi crittograﬁci moderni a chiave simmetrica è il DES (Data Encryption Standard), un algoritmo simmetrico con chiave privata da 64 bit, sviluppato per l’IBM nel 1976 e diventato uno standard negli USA per la protezione di dati sensibili.
Il DES inizialmente ha suscitato molte discussioni per via della sua chiave di cifratura corta. Si supponeva che dietro questa scelta vi fosse la National Security Agency (NSA) e l'inserimento di una backdoor. Con la potenza di calcolo disponibile attualmente si può forzare una chiave DES in poche ore, esaminando tutte le possibili combinazioni (Attacco di forza bruta).
Una caratteristica desiderata per ogni algoritmo di criptazione è quello che prende il nome di effetto valanga: un cambiamento di pochi bit nel plaintext deve provocare un cambiamento di quanti più bit nel ciphertext. Il DES possiede un forte effetto valanga.
Attualmente il DES non è più utilizzato come standard negli USA ed è stato rimpiazzato dal AES (Advanced Encryption Standard) che utilizza una chiave che può essere di 128, 192 o 256 bit.
Gli algoritmi simmetrici presentano alcuni limiti; quello più evidente è che le persone per comunicare devono essere in possesso della stessa chiave e, di fatto, questo limita la diffusione e il suo utilizzo.

![alt text](/img/image003.gif "CRITTOGRAFIA SIMMETRICA")

###	CRITTOGRAFIA ASIMMETRICA <a name="CRITTOGRAFIA_ASIMMETRICA"></a>
L’idea alla base della crittograﬁa asimmetrica è quello di avere due chiavi diverse, una pubblica per cifrare ed una privata per decifrare, che deve essere mantenuta assolutamente segreta.
Formalmente è necessario trovare una funzione (“il lucchetto”) la cui trasmissione su canali insicuri non comprometta l’algoritmo, che sia facile da applicare (parte pubblica che chiude il lucchetto) ma difﬁcile da invertire (parte privata che apre il lucchetto).
Questo meccanismo è implementato negli algoritmi di crittograﬁa asimmetrici, come ad esempio nell’algoritmo RSA.
Con la crittografia asimmetrica si risolvono due problemi, quello della riservatezza e quello della autenticità del mittente semplicemente utilizzando le chiavi in modo diverso:

*	Per garantire la riservatezza si cifra il messaggio con la chiave pubblica e solo il possessore della chiave privata sarà in grado di decifrarlo.
*	Per garantire l’autenticità del mittente invece il messaggio viene cifrato con la chiave privata e solo con la corrispondente chiave pubblica sarà possibile decifrare il messaggio. La chiave pubblica sarà conservata in registri consultabili ma gestiti in modo sicuro. Questo si chiama firma elettronica. In più, oltre a garantire il mittente, è possibile garantire anche il contenuto del messaggio generando un “hashing” dello stesso, aggiungendolo in fondo al messaggio.

Se si volesse garantire sia la riservatezza che l’autenticità, basterebbe combinare entrambe le tecniche.

![alt text](/img/image004.jpg "CRITTOGRAFIA ASIMMETRICA")

Il principale svantaggio degli algoritmi a cifratura asimmetrica sta nella complessità dei calcoli che rendono poco efficiente la loro implementazione soprattutto con l’aumentare della lunghezza della chiave. 
In pratica, per motivi prestazionali, il client e il server usano questa tecnica per scambiarsi una chiave simmetrica in modo sicuro e poi passano a un algoritmo di crittografia tradizionale. 
Per evitare la necessità di scambiare in anticipo in modo sicuro le chiavi pubbliche, si usano i certificati: Un certificato contiene una chiave pubblica autenticata mediante la firma digitale di una Certification Authority (CA); chi riceve il certificato può verificare direttamente l’autenticità della chiave pubblica usando la chiave pubblica della CA (che deve essere nota). 
Nel corso degli anni le raccomandazioni sulla lunghezza della chiave sono mutate per via della maggior potenza di calcolo degli elaboratori moderni, attualmente si consiglia una chiave a 2048 bit.

###	L’ARGORITMO RSA <a name="ARGORITMO_RSA"></a>
L’algoritmo RSA fu descritto nel 1977 da Rivest, Shamir e Adleman al MIT e fu brevettato nel 1983. Il cuore della crittograﬁa asimmetrica è una funzione facile da computare ma difﬁcile da invertire, a meno di non conoscere un particolare dato (la chiave): l’algoritmo RSA “lavora” sfruttando i numeri primi e come chiave utilizza un numero n ottenuto proprio dal prodotto di due numeri primi p e q, cioè n = p · q.
Per decrittare un messaggio cifrato con RSA è necessario decomporre la chiave n nei due numeri primi p e q: questo è computazionalmente impegnativo da ottenere, basti pensare che nel 2005 un gruppo di ricerca riuscì a scomporre un numero di 640 bit in due numeri primi da 320 bit impiegando per cinque mesi un cluster con 80 processori da 2,2 GHz.
Un attuale utilizzo è quello di sfruttare RSA per codiﬁcare un unico messaggio contenente una chiave segreta, tale chiave verrà poi utilizzata per scambiarsi messaggi tramite la cifratura simmetrica (ad esempio AES).
Il funzionamento dell’algoritmo RSA è il seguente:
1.	Alice deve spedire un messaggio segreto a Bob;
2.	Bob sceglie due numeri primi molto grandi e li moltiplica tra loro (generazione delle chiavi);
3.	Bob invia ad Alice “in chiaro” il numero che ha ottenuto;
4.	Alice usa questo numero per crittografare il messaggio;
5.	Alice manda il messaggio cifrato a Bob, che chiunque può vedere ma non decifrare;
6.	Bob riceve il messaggio e utilizzando i due fattori primi, che solo lui conosce, decifra il messaggio.

La forza (o la debolezza) dell’algoritmo si basa sull’assunzione mai dimostrata (nota come RSA assumption) che il problema di calcolare un numero composto di cui non si conoscono i fattori sia computazionalmente non trattabile.
Questo sistema però comporta un problema, cioè che le funzioni matematiche che generano il codice cifrato e quelle inverse impiegano troppo tempo per essere utilizzate per la cifratura di interi documenti, per questo sono nati i sistemi di crittografia misti che uniscono la tecnica a cifratura asimmetrica per scambiarsi una chiave segreta che verrà utilizzata per una normale comunicazione basata su crittografia simmetrica. Infatti i vantaggi di un metodo compensano gli svantaggi dell’altro.

###	IL PROTOCOLLO SSL/TLS <a name="PROTOCOLLO_TLS"></a>
Lo standard più diffuso per la protezione dei servizi offerti tramite Internet è Secure Socket Layer (SSL) ed il suo successore Transport Layer Security (TLS): si tratta di un insieme di protocolli crittograﬁci che aggiungono funzionalità di cifratura e autenticazione a protocolli preesistenti al livello di sessione. Questo protocollo è nato al ﬁne di garantire la privacy delle trasmissioni su Internet, permettendo alle applicazioni client/server di comunicare in modo da prevenire le intrusioni, le manomissioni e le falsiﬁcazioni dei messaggi.
Il protocollo SSL/TLS garantisce la sicurezza del collegamento mediante tre funzionalità fondamentali: 
1.	privatezza del collegamento: la riservatezza del collegamento viene garantita mediante algoritmi di crittograﬁa a chiave simmetrica (ad esempio DES e AES);
2.	autenticazione: l’autenticazione dell’identità viene effettuata con la crittograﬁa a chiave pubblica (per esempio RSA): in questo modo si garantisce ai client di comunicare con il server corretto, introducendo a tale scopo anche meccanismi di certiﬁcazione sia del server che del client;
3.	affidabilità: il livello di trasporto include un controllo sull’integrità del messaggio con un sistema detto MAC (Message Authentication Code) che utilizza funzioni hash sicure come SHA e MD5: avviene la veriﬁca di integrità sui dati spediti in modo da avere la certezza che non siano stati alterati durante la trasmissione.

![alt text](/img/image005.png "PROTOCOLLO SSL/TLS")

TSL è un protocollo di livello 5 (sessione) che opera quindi al di sopra del livello di trasporto composto da due livelli:
1.	TLS Record Protocol: opera a livello più basso, direttamente al di sopra di un protocollo di trasporto affidabile come il TCP ed è utilizzato per i protocolli del livello superiore, tra cui l’Handshake Protocol, offrendo in questo modo i servizi di sicurezza;
2.	TLS Handshake Protocol: si occupa della fase di negoziazione, in cui si autentica l’interlocutore e si stabiliscono le chiavi segrete condivise.

##	JAVA: CHIAVI, CERTIFICATI E SOCKET SSL <a name="JAVA_CHIAVI_CERTIFICATI_SOCKET_SSL"></a>
###	GESTIRE CHIAVI E CERTIFICATI IN JAVA (KEYTOOL) <a name="KEYTOOL"></a>
Il Java Development Kit include un tool (da usare da linea di comando) per gestire chiavi e certificati:
```bash
keytool
```
Le chiavi pubbliche e private sono memorizzate in un keystore e i certificati ritenuti “fidati” sono memorizzati in un truststore. Il formato del keystore e del truststore è proprietario, ma keytool offre funzioni per import/export di chiavi e certificati nei formati standard.
Per generare una coppia di chiavi in un keystore il comando è:
```bash
keytool -genkey [opzioni] -alias nome -keylag RSA  -validity giorni -keystore keystore -keysize bits
```
Il tool richiede alcune informazioni sull’identità della persona che genera le chiavi, che saranno memorizzate all’interno delle chiavi stesse ed è protetto da una password.
Ecco un esempio di che cosa avviene durante la creazione di una coppia di chiavi:

![alt text](/img/image006.png "Keytool")

È possibile visualizzare il contenuto di un keystore con il comando:
```bash
keytool -list -v -keystore keystore
```
Per quanto riguarda invece il processo per generare un certificato, richiede tre passi:
1.	creazione di una Certificate Request a partire dalla chiave pubblica nel keystore
2.	invio della Certificate Request alla Certification Authority (CA), che produrrà il certificato
3.	importazione del certificato della CA nel truststore

Se non si ha a disposizione una CA, si può generare un self-signed certificate, quindi senza la garanzia sull’identità data dalla CA, ma è adeguato se i due end-point si fidano reciprocamente e possono scambiarsi i certificati in maniera sicura.
Quindi i passi diventano:
1.	generazione del certificato dalla chiave pubblica nel keystore
2.	importazione del certificato nel truststore

Per eseguire il primo passo, cioè generare il certificato la sintassi sarà:
```bash
keytool -export -alias nome -keystore keystore -rfc -file fileCertificato
```
Questo è quello che succede durante la generazione di un certificato:

![alt text](/img/image007.png "keytool")

A questo punto è necessario importare il certificato nel truststore:
```bash
keytool -import -alias nome -keystore truststore -file fileCertificato
```

Questo è quello che succede durante l’importazione del certificato. Verrà mostrato il proprietario, l’ente emittente e le impronte del certificato nei vari algoritmi di hashing:
![alt text](/img/image008.png "keytool")


###	L’USO DEI SOCKET SSL/TLS IN JAVA <a name="SOCKET_TLS_IN_JAVA"></a>
##	UN SEMPLICE WEB SERVER HTTPS IN JAVA <a name="WEB_SERVER_HTTPS_IN_JAVA"></a>
###	INTRODUZIONE <a name="#INTRODUZIONE"></a>
###	CICLO DI VITA DEL WEB SERVER <a name="CICLO_VITA_DEL_WEB_SERVER"></a>
###	CREAZIONE DEL SERVER SOCKET <a name="CREAZIONE_DEL_SERVER_SOCKET"></a>
###	ATTESA DEL CLIENT <a name="ATTESA_DEL_CLIENT"></a>
###	HTTP REQUEST <a name="HTTP_REQUEST"></a>
###	HTTP RESPONSE <a name="HTTP_RESPONSE"></a>
###	IL COMPORTAMENTO DI UN BROWSER INTERROGANDO IL WEB SERVER <a name="INTERROGANDO_IL_WEB_SERVER"></a>
##	ANALISI DEI PACCHETTI CON WIRESHARK <a name="ANALISI_DEI_PACCHETTI_CON_WIRESHARK"></a>
###	INTRODUZIONE <a name="INTRODUZIONE"></a>
###	HTTP SNIFFING CON WIRESHARK <a name="HTTP_SNIFFING_CON_WIRESHARK"></a>
###	HTTPS SNIFFING CON WIRESHARK <a name="HTTPS_SNIFFING_CON_WIRESHARK"></a>
##	CONCLUSIONI <a name="CONCLUSIONI"></a>
##	RIFERIMENTI <a name="RIFERIMENTI"></a>


