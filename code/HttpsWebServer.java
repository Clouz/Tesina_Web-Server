import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.BindException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.Scanner;

import javax.net.ssl.*;

public class HttpsWebServer {

	private SSLServerSocketFactory serverFactory;
	private SSLServerSocket server;
	// Porta su cui si metterà in ascolto il webServer
	private int port;
	// Nome del Web Server
	private String serverName;
	
	// Contengono la request line HTTP splittata in 3 variabili
	String method;
	private URI uri;
	String httpVersion;
	
	// La Home del Web Server dove posizionare il sito
	private String home;

	public HttpsWebServer(int port, String home) {
		// Inizializzo le variabili
		this.serverName = "Piccolo HttpsWebServer 1.0 by Claudio Mola";
		this.port = port;
		this.home = home;

		System.out.println(serverName);
	}

	public void creaServer() throws IOException {
		try {
			// Fornisco le chiavi ed il certificato con le relative password
			System.setProperty("javax.net.ssl.keyStore", "C:\\_Certificati\\keystore.jks");
			System.setProperty("javax.net.ssl.keyStorePassword", "password");
			System.setProperty("javax.net.ssl.trustStore", "C:\\_Certificati\\truststore.jks");
			System.setProperty("javax.net.ssl.trustStorePassword", "password");

			// SSLServerSocketFactory mi permette di creare un ServerSocket
			serverFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
			server = (SSLServerSocket) serverFactory.createServerSocket(port);
			System.out.println("Server creato con successo");
			System.out.println("Server: " + new Date() + "\n\n");

		} catch (BindException e) {
			System.out.println("Server: Assicurarsi che un'altra istanza del" 
					+ " programma non sia già in esecuzione");
			System.out.println("Server: " + e);
			System.exit(1);

		} catch (Exception e) {
			System.out.println("Server: Assicurarsi di aver posizionato i file" 
					+ " \"keystore.jks\" e \"truststore.jks\"");
			System.out.println("Server: nella cartella \"C:\\_Certificati\" e" 
					+ " di aver creato il file \"index.html\" nella cartella "
					+ this.home);
			System.out.println("Server: " + e);
			System.exit(1);
		}
	}

	// Attendo una richiesta dal client e rispondo
	public void connessione() {
		try {
			// Mi metto in attesa del client
			System.out.println("Server: In attesa di un client sulla porta " 
					+ server.getLocalPort() + "...");
			SSLSocket client = (SSLSocket) server.accept();

			// Mostro le informazioni sul client
			System.out.println(
					"Server: nuovo client " + client.getInetAddress().getHostAddress() + ":" 
					+ client.getPort());
			System.out.println("Server: protocollo utilizzato " 
					+ client.getSession().getProtocol());
			System.out.println("Server: " + new Date());

			// Stream per leggere la richiesta del client
			Scanner input = new Scanner(client.getInputStream());

			// Recupero la richiesta HTTP del client
			if (clientHeader(client, input)) {

				// Invio il file richiesto al client
				// solo se esiste una richiesta valida
				inviaFile(client);
			}

			// chiudo la connessione con il client
			client.close();
			input.close();

			System.out.println("Server: connessione terminata\n\n");

		} catch (Exception e) {
			System.out.println("Server: Errore 1 - " + e);
		}
	}

	// Recupero la richiesta HTTP del client
	private Boolean clientHeader(SSLSocket client, Scanner input) throws Exception {

		uri = new URI(""); // contiene il percorso del file richiesto dal client
		String inputTxt = ""; // stringa di supporto
		Boolean status = true; // Esiste una richiesta HTTP?

		try {
			// Verifico se il client ha inviato una intestazione
			// se non lo ha fatto restituisco "false"
			if (input.hasNext()) {
				inputTxt = input.nextLine();
				
				//Attraverso una espressione regolare divido la stringa
				String[] split = inputTxt.split("\\s[a-zA-z]*", 3);
				method = split[0];
				uri = new URI(split[1]);
				httpVersion = split[2];
				
			} else
				status = false;

			// Mostro il resto dell'intestazione
			while (!inputTxt.isEmpty()) {
				System.out.println("Request header: " + inputTxt);
				inputTxt = input.nextLine();
			}

		} catch (Exception e) {
			System.out.println("Server: Errore 2 - " + e);
		}

		return status;
	}

	// Invio il file richiesto al client
	private void inviaFile(SSLSocket client) throws IOException {
		try {
			// Provo a recuperare un percorso valido dalla combinazione della
			// directory Home più quanto richiesto dal client
			File file = trovaFile();

			// Creo gli stream, in input dal file in output sul socket
			FileInputStream input = new FileInputStream(file);
			BufferedOutputStream output = new BufferedOutputStream(client.getOutputStream());

			// Il messaggio di risposta per il client spedificando la versione
			// del protocollo HTTP,
			// lo status code ed una spiegazione
			String responseHeader = "HTTP/1.0 200 OK\r\nDate: " + new Date() + "\r\nServer: " 
					+ this.serverName + "\r\n\r\n";
			output.write(responseHeader.getBytes());

			// Leggo ed invio il file
			while (input.available() > 0)
				output.write(input.read());

			// Forzo l'invio e chiudo gli stream
			output.flush();
			output.close();
			input.close();

		} catch (Exception e) {
			// Nel caso non esista il file richiesto sarà generata una eccezione
			// invierò al client un messaggio di errore (404 not found)
			// più la relativa pagina come fatto per gli altri file
			System.out.println("Server: 404 Not Found");

			File file = Paths.get(home).resolve("Error.html").toFile();

			FileInputStream input = new FileInputStream(file);
			BufferedOutputStream output = new BufferedOutputStream(client.getOutputStream());

			String httpResponse = "HTTP/1.0 404 Not Found\r\n\r\n";
			output.write(httpResponse.getBytes());

			while (input.available() > 0) {
				output.write(input.read());
			}

			output.flush();
			output.close();
			input.close();
		}
	}

	// Provo a recuperare un percorso valido dalla conbinazione della directory
	// Home più quanto richiesto dal client
	private File trovaFile() {

		String defaultFileName = "index.html"; // file da cercare se non
												// specificato
		Path root = Paths.get(home); // Percorso sul server dove cercare i file
		Path joint; // Percorso dato dall'unione di root più quanto richiesto
					// dal client

		// Unisco il percorso
		joint = Paths.get(root.toString(), uri.getPath());

		if (!joint.toFile().exists()) // Se non esiste lo stampo a console
			System.out.println("Server: File non trovato");
		else if (joint.toFile().isDirectory()) { // Se è una directory aggiungo
													// il "defaultFileName"
			System.out.println("Server: Provo a cercare " + defaultFileName);
			joint = Paths.get(joint.toString(), defaultFileName);
		}

		System.out.println("Server: Richiesta " + uri.getPath());
		System.out.println("Server: File inviato " + joint);

		return joint.toFile(); // Restituisco il percorso di tentativo
	}

	public static void main(String[] args) {

		// Inizializzo il web server specificando la porta e l'indirizzo di home
		HttpsWebServer server = new HttpsWebServer(443, "C:/_File/");

		try {
			// Creo il server
			server.creaServer();

			while (true)
				// Mi metto in ascolto
				server.connessione();

		} catch (Exception e) {
			System.out.println(e);
		}
	}
}
