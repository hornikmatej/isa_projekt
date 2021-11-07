/**
 * @author Matej Hornik, xhorni20
 * @brief ISA Klient POP3 s podporou TLS
 * @date 10.10.2021
 */

#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <unistd.h>
#include <chrono>
#include <thread>
/* OpenSSL headers */

# include <openssl/bio.h>
# include <openssl/ssl.h>
# include <openssl/err.h>


/**
 * Struktura uchovava konfiguracne udaje
 */
struct cfg {
    std::string server;
    std::string username;
    std::string password;
    std::string outdir;
    int port = 110;
    std::string certfile;
    std::string certdir;
    bool del_mails = false;
    bool new_mails = false;
    bool T_enc = false;
    bool S_enc = false;
    BIO* bio;

} cfg;

const char* usage = "popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>\n";

/**
 * Trieda pre zachytavanie vyjimiek
 */
class MyException {
public:
  std::string str_what;

  MyException() { str_what = ""; }

  MyException(std::string s) {
     str_what = s;
   }
};


/**
 * Funkcia zisti ci dani argument existuje a vrati jeho parameter
 * @param begin zaciatok ukazatela na zadane argumenty
 * @param end koniec ukazatela na zadane argumenty
 * @param option nazov hladaneho argumentu
 * @param required znaci ci je argument povinny
 * @return parameter zadaneho argumentu
 */
char* getCmdOption(char ** begin, char ** end, const std::string & option, bool required){
    char ** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end){
        char * argm = *itr;
        if (argm[0] == '-'){
            fprintf(stderr, "%s", usage);
            exit(1);
        }
        return argm;
    }
    fprintf(stderr, "%s", usage);
    exit(1);
}

/**
 * Funkcia zisti ci dani argument existuje
 * @param begin zaciatok ukazatela na zadane argumenty
 * @param end koniec ukazatela na zadane argumenty
 * @param option nazov hladaneho argumentu
 * @return ci zadani option argument existuje
 */
bool cmdOptionExists(char** begin, char** end, const std::string& option){
    return std::find(begin, end, option) != end;
}

/**
 * Funkcia spracovava argumenty a uklada ich do konfiguracnej struktury
 * @param argc pocet argumentov na vstupe
 * @param argv ukazatel na zoznam argumentov
 */
void parse_arguments(int argc, char **argv){
    //minimalne 6 argumentov zadanych aj s nazvom funkcie
    if (argc < 6){
        fprintf(stderr, "%s", usage);
        exit(1);
    }

    cfg.server = std::string(argv[1]);

    //kontrola ci existuje argument -a
    char * auth_f = getCmdOption(argv, argv + argc, "-a", true);
    if (auth_f){
        FILE *file;
        if ((file = fopen(auth_f, "r"))) {
            fclose(file);
        } 
        else {
            fprintf(stderr, "ERROR: Konfiguracni soubor s autentizacnimi udajmi neexistuje\n");
            exit(1);
        }
        std::string myText;

        std::ifstream MyReadFile(auth_f);

        //kontrola formatu konfiguracneho suboru
        int line_n = 0;
        std::regex un("^(username = )([^\\s]+)$");
        std::regex pw("^(password = )([^\\s]+)$");
        std::smatch match;
        while (getline (MyReadFile, myText)) {
            line_n++;
            if (line_n == 1){
                if (!std::regex_match(myText, un)){
                    fprintf(stderr, "ERROR: Zly konfiguracni soubor\n");
                    exit(1);
                }
                regex_search(myText, match, un);
                cfg.username = match.str(2);
            }
            else if (line_n == 2){
                if (!std::regex_match(myText, pw)){
                    fprintf(stderr, "ERROR: Zly konfiguracni soubor\n");
                    exit(1);
                }
                regex_search(myText, match, pw);
                cfg.password = match.str(2);
            }
            else {
                fprintf(stderr, "ERROR: Zly konfiguracni soubor\n");
                exit(1);
            }
        }
        MyReadFile.close();
    }

    //kontrola ci existuje argument -o
    char * outdir = getCmdOption(argv, argv + argc, "-o", true);
    if (outdir){
        if(!std::filesystem::is_directory(std::filesystem::status(outdir))){
            fprintf(stderr, "ERROR: Zadany adresar pre emaily neexistuje\n");
            exit(1);
        }
        cfg.outdir = std::string(outdir);
        if (cfg.outdir.back() != '/'){
                cfg.outdir += "/";
            }
    }

    if(cmdOptionExists(argv, argv + argc, "-d")){
        cfg.del_mails = true;
    }
    if(cmdOptionExists(argv, argv + argc, "-n")){
        cfg.new_mails = true;
    }

    if(cmdOptionExists(argv, argv + argc, "-T")){
        if (cmdOptionExists(argv, argv + argc, "-S")){
            fprintf(stderr, "%s", usage);
            exit(1);
        }
        cfg.T_enc = true;
        cfg.port = 995;
    }
    if(cmdOptionExists(argv, argv + argc, "-S")){
        if (cmdOptionExists(argv, argv + argc, "-T")){
            fprintf(stderr, "%s", usage);
            exit(1);
        }
        cfg.S_enc = true;
    }

    if(cmdOptionExists(argv, argv + argc, "-c")){
        if (cfg.T_enc == false && cfg.S_enc == false){
            fprintf(stderr, "%s", usage);
            exit(1);
        }
        char * certf = getCmdOption(argv, argv + argc, "-c", false);
        if (certf){
            
            //kontrola existencie certifikacneho suboru
            FILE *cfile;
            if ((cfile = fopen(certf, "r"))) {
                fclose(cfile);
            } 
            else {
                fprintf(stderr, "ERROR: Subor s certifikaty neexistuje\n");
                exit(1);
            }
            cfg.certfile = std::string(certf);
        }
    }

    if(cmdOptionExists(argv, argv + argc, "-C")){
        if (cfg.T_enc == false && cfg.S_enc == false){
            fprintf(stderr, "%s", usage);
            exit(1);
        }
        char * certdir = getCmdOption(argv, argv + argc, "-C", false);
        //kontrola existencie adresara
        if (certdir){
            if(!std::filesystem::is_directory(std::filesystem::status(certdir))){
                fprintf(stderr, "ERROR: Zadany adresar s certifikaty neexistuje\n");
                exit(1);
            }
            
            cfg.certdir = std::string(certdir);
            if (cfg.certdir.back() != '/'){
                cfg.certdir += "/";
            }
        }
    }

    if(cmdOptionExists(argv, argv + argc, "-p")){
        char * port = getCmdOption(argv, argv + argc, "-p", false);
        if (port){
            try {
                // nastavenia cisla portu ak bolo zadane
                cfg.port = std::stoi(std::string(port));
                if (cfg.port < 0 || cfg.port >  65535) {
                    fprintf(stderr, "ERROR: Cislo portu je zle zadane\n");
                    exit(1);
                }
            } catch (std::exception const&) {
                fprintf(stderr, "ERROR: Cislo portu je zle zadane\n");
                exit(1);
            }
        }
    }
    // ak nachadzal iny argument na vstupe aky nieje povoleny
    std::string tmp;
    for (int i = 2; i < argc; i++){
        tmp = std::string(argv[i]);
        if (tmp == "-p" || tmp == "-c" || tmp == "-C" || tmp == "-a" || tmp == "-o"){
            i++;
        }
        else if (tmp == "-T" || tmp == "-S" || tmp == "-d" || tmp == "-n"){}
        else {
            fprintf(stderr, "%s", usage);
            exit(1);
        }
    }
}
/**
 * Funkcia precita zo socketu odpoved a vrati ju ako std::string
 * @throws MyException chybovu hlasku v pripade ak sa nepodari precitat odpoved
 * @return string s odpovedou servera
 */
std::string get_response(){
    int len = 1024;
    char buf[len];
    std::fill_n(buf, len, 0);

    int x = BIO_read(cfg.bio, buf, len);
    if(x == 0){
        throw MyException ("ERROR: Spojenie bolo ukoncene (chyba v komunikacii)\n");
    }
    else if(x < 0){
        throw MyException ("ERROR: Nastala chyba pri komunikacii so serverom\n");
    }

    if (buf[0] == '-'){
        throw MyException("ERROR: Server nedokazal odpovedat na poziadavok\n");
    }

    return std::string(buf);
}

/**
 * Funkcia zasle serveru prikaz na vykonanie
 * @throws MyException chybovu hlasku v pripade ak sa nepodari zaslat prikaz
 */
void send_command(std::string command){
    command = command + "\r\n";
    char* c_command = const_cast<char*>(command.c_str());
    int code = BIO_puts(cfg.bio, c_command);

    if(code == 0){
        throw MyException("ERROR: Spojenie bolo ukoncene (chyba v komunikacii)\n");
    }
    else if(code < 0){
        throw MyException ("ERROR: Nastala chyba pri komunikacii so serverom\n");
    }
}

/**
 * Funkcia vytvori nezabezpecne pripojenie so serverom
 * @param server Nazov servera 
 * @param port port na ktorom je server
 * @return BIO objekt s vytvorenim pripojenim
 */
BIO *create_connection(std::string server, int port){
    std::string hostname = server + ":"+std::to_string(port);
    char* host_name = const_cast<char*>(hostname.c_str());

    BIO *new_bio = BIO_new_connect(host_name);
    if(new_bio == NULL){
        fprintf(stderr, "ERROR: Chyba pri vytvarani spojenia\n");
        exit(1);
    }

    if(BIO_do_connect(new_bio) <= 0){
        fprintf(stderr, "ERROR: Nepodarilo sa pripojit k serveru\n");
        exit(1);
    }

    return new_bio;
}

/**
 * Funkcia vytvori zabezpecne pripojenie so serverom
 * @param bio objekt pre zabezpecene pripojenie
 * @param server Nazov servera 
 * @param port port na ktorom je server
 */
void create_sec_connection(BIO * bio, std::string server, int port){
    std::string hostname = server + ":"+std::to_string(port);
    char* host_name = const_cast<char*>(hostname.c_str());

    BIO_set_conn_hostname(bio, host_name);

    if(BIO_do_connect(bio) <= 0){
        fprintf(stderr, "ERROR: Nepodarilo sa pripojit k serveru(SSL)\n");
        exit(1);
    }
}

/**
 * Funkcia autentifikuje uzivatela na pop3 serveri
 * @param uname username pouzivatela
 * @param pass heslo uzivatela
 */
void authentificate(std::string uname, std::string pass){
    try{
        send_command("USER " + uname);
        std::string resp = get_response();

        send_command("PASS " + pass);
        resp = get_response();
    }
    catch (MyException e){
        std::cerr << e.str_what << std::endl;
        exit(1);
    }
}

/**
 * Funkcia ulozi email do suboru
 * @param email email na ulozenie
 * @param filename nazov subora ako sa ma email ulozit
 */
void save_email(std::string email, std::string filename){
    std::ofstream MyFile(cfg.outdir + filename);
    MyFile << email;
    MyFile.close();

}

/**
 * Funckia stiahne email zo serveru 
 * @param bio objekt na s pripojenim na server
 * @param i cislo emailu na stiahnutie
 * @throws MyException pri zlihani vyhodi chybu
 * @return stiahnuty email
 */
std::string download_email(BIO * bio, int i){
    send_command("RETR " + std::to_string(i));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    std::string resp = "";
    
    //buffer pre email
    unsigned int len = 1024;
    char buf[len];
    bool first_read = true;

    //citanie zo socketu az dokym nenarazim na koniec spravy "\r\n.\r\n"
    while (true){
        std::fill_n(buf, len, 0);
        int x = BIO_read(cfg.bio, buf, len);
        if(x == 0){
            throw MyException ("ERROR: Spojenie bolo ukoncene (chyba v komunikacii)\n");
        }
        else if(x < 0){
            throw MyException ("ERROR: Nastala chyba pri komunikacii so serverom\n");
        }
        //kontrola odpovedi od servera
        if (buf[0] == '-' && first_read){
            throw MyException("ERROR: Server nedokazal odpovedat na poziadavok\n");
        }
        first_read = false;

        std::string tmp_resp = std::string (buf);
        if (tmp_resp.length() > len){
            tmp_resp.erase(tmp_resp.end() - (tmp_resp.length() - len), tmp_resp.end());
        }
        //kontrola konca spravy
        resp = resp + tmp_resp;
        if (resp.find("\r\n.\r\n") != std::string::npos){
            break;
        }
    }
    resp.erase(resp.length()-3, resp.length());
    resp.erase(0, resp.find("\r\n") + 2);
    return resp;
}

/**
 * Funckia stiahne vsetky emaily so servera, vola funkciu download_email()
 * @param bio objekt s pripojenim na server
 * @param new_mails ci sa maju stiahnut len nove emaily
 */
void download_all_emails(BIO *bio, bool new_mails){
    //zistenie poctu emailov
    send_command("STAT");
    std::string resp;
    try {
        resp = get_response();
    }
    catch (MyException e){
        std::cerr << e.str_what;
        exit(1);
    }

    //kontrola odpovedi a nacitanie poctu emailov do premeny
    std::regex nom("^(\\+OK )(\\d+)");
    std::smatch match;
    regex_search(resp, match, nom);
    int n_emails = std::stoi(match.str(2));

    std::string email;
    int c_nm = 0;
    // postupne stahovanie emailov
    for (int i = 1; i <= n_emails; i++){
        try {
            email = download_email(bio, i);
        }
        catch (MyException e){
            std::cerr << e.str_what;
            exit(1);
        }
        // najdenie message id sprave pre nazov subora na ulozenie
        std::regex mid("([Mm][Ee][Ss][Ss][Aa][Gg][Ee]-[Ii][Dd]: )(.+)");
        std::smatch mat;
        regex_search(email, mat, mid);
        //ak sa stahuju nove emaily skontroluje sa ci je uz email stiahnuty
        if (new_mails){
            std::ifstream ifile;
            ifile.open(cfg.outdir + mat.str(2));
            //kontrola ci existuje uz dany email v adreasi zadanom -o
            if(!ifile) {
                save_email(email, mat.str(2));
                c_nm++;
            }
            else {
                ifile.close();
            }
        }else {
            save_email(email, mat.str(2));
        }
    }
    //vypis informacie o stiahnutych emailoch
    if (new_mails){
        std::cout << "Staženy " + std::to_string(c_nm) + " nových zpráv\n";
    }else {
        std::cout << "Staženy " + std::to_string(n_emails) + " zprávy\n";
    }

}

/**
 * Funckia vymaze emaily zo servera
 * @param bio objekt s pripojenim na server
 */
void delete_emails(BIO *bio){
    //zistenie poctu emailov na serveri
    send_command("STAT");
    std::string resp;
    try {
        resp = get_response();
    }
    catch (MyException e){
        std::cerr << e.str_what;
        exit(1);
    }
    //ulozenie poctu emailov do premenej
    std::regex nom("^(\\+OK )(\\d+)");
    std::smatch match;
    regex_search(resp, match, nom);
    int n_emails = std::stoi(match.str(2));
    //mazanie emailov a kontrola odpovedi servera
    for (int i = 1; i <= n_emails; i++){
        send_command("DELE " + std::to_string(i));
        try {
            resp = get_response();
        }
        catch (MyException e){
            std::cerr << e.str_what;
            exit(1);
        }
    }
    //vypis informacie na vystup
    std::cout << "Zmazaných " + std::to_string(n_emails) + " zpráv\n";
}


/**
 * Funckia riadi pripojenia na pop3 server
 * @param secure ak sa jedna o sifrovane pripojenie (-T)
 * @param ssl ukazatel na SSL strukturu
 * @param ukazatel na SSL_CTX strukturu vytvorenu pomocou SSL_ctx_new()
 */
void pop3session(bool secure, SSL * ssl, SSL_CTX * ctx){

    std::string resp;
    //sifrovane spojenie
    if (secure){
        create_sec_connection(cfg.bio, cfg.server, cfg.port);
        try {
            resp = get_response();
        }
        catch (MyException e){
            std::cerr << e.str_what;
            exit(1);
        }
        //overenie certifikatov ktore boli zadane po pripojeny na server
        if(SSL_get_verify_result(ssl) != X509_V_OK){
            fprintf(stderr, "ERROR: Nepodarilo sa overit certifikat\n");
            exit(1);
        }
    }
    //nesifrovane spojenie
    else{
        cfg.bio = create_connection(cfg.server, cfg.port);
        try {
            resp = get_response();
        }
        catch (MyException e){
            std::cerr << e.str_what;
            exit(1);
        }
    }
    //ak sa jedna o -S komunikaciu
    //sifrovana komunikacia zacina az po zaslani prikazu STLS pop3 serveru
    if (cfg.S_enc){
        send_command("STLS");
        try {
            resp = get_response();
        }
        catch (MyException e){
            std::cerr << e.str_what;
            exit(1);
        }
        //nastavenie zabezpeceneho pripojenia
        BIO *ret = NULL, *ssl_bio = NULL;
        if ((ssl_bio = BIO_new_ssl(ctx, 1)) == NULL){
            fprintf(stderr, "ERROR: Nepodarilo sa prejst na sifrovane spojenie\n");
            exit(1);
        }
        if ((ret = BIO_push(ssl_bio, cfg.bio)) == NULL){
            fprintf(stderr, "ERROR: Nepodarilo sa prejst na sifrovane spojenie\n");
            exit(1);
        }
        cfg.bio = ret;
        BIO_get_ssl(cfg.bio, & ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        //overenie certifikatov ktore boli zadane po pripojeny na server
        if(SSL_get_verify_result(ssl) != X509_V_OK){
            fprintf(stderr, "ERROR: Nepodarilo sa overit certifikat\n");
            exit(1);
        }
    }
    //autentifikacia
    authentificate(cfg.username, cfg.password);

    //riadenie co ma server vykonat na zaklade poziadavky uzivatela
    //ak bolo zadane aj -n a -d tak sa vymazu spravy na serveri
    if (cfg.del_mails){
        delete_emails(cfg.bio);
    }
    else if (cfg.new_mails){
        download_all_emails(cfg.bio, true);
    }
    else {
        download_all_emails(cfg.bio, false);
    }


    //zaslanie ukoncujuceho prikazu pop3 serveru
    send_command("QUIT");
    try {
        resp = get_response();
    }
    catch (MyException e){
        std::cerr << e.str_what;
        exit(1);
    }
    //uvolnenie BIO objektu s pripojenim
    BIO_free_all(cfg.bio);
}

/**
 * Nastavi sifrovane spojenie a skontroluje certifikaty
 * @param ctx struktura zo sifrovanymi udajmi z funkcie SSL_ctx_new()
 * @param S_enc ak sa jedna o sifrovanu komunikaciu typu -S, po zadani prikazu STLS pop3 serveru
 * @return bio objekt s pripravenym sifrovanym spojenim
 */ 
BIO * set_sec_conn(SSL_CTX * ctx, bool S_enc){
    //kontrola certifikatu zadaneho -c
    if (!cfg.certfile.empty()){
            char* path = const_cast<char*>(cfg.certfile.c_str());
            if(! SSL_CTX_load_verify_locations(ctx, path, NULL)){
                std::cerr << "ERROR: Nepodarilo sa nacitat certifikat" << std::endl;
                exit(1);
            }
    }
    //kontrola zlozky certifikatov zadaneho s -C
    if (!cfg.certdir.empty()){
        char* path = const_cast<char*>(cfg.certdir.c_str());
        //pripravenie zlozky
        std::string cmd = "c_rehash " + cfg.certdir + " > /dev/null";
        char * command = const_cast<char*>(cmd.c_str());
        system(command);
        
        if(! SSL_CTX_load_verify_locations(ctx, NULL, path)){
            std::cerr << "ERROR: Nepodarilo sa nacitat adresar s certifikaty" << std::endl;
            exit(1);
        }
    }
    //kontrola defaultnych certifikatov ak nebolo zadane -c ani -C
    if (cfg.certfile.empty() && cfg.certdir.empty()){
        SSL_CTX_set_default_verify_paths(ctx);
    }
    if (S_enc){
        return NULL;
    }
    BIO * bio = BIO_new_ssl_connect(ctx);
    return bio;
}


int main(int argc, char **argv){

    parse_arguments(argc, argv);
    //nastavnie openssl 
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if (cfg.T_enc || cfg.S_enc){
        //vytvorenie potrebnych struktur pre sifrovanu komunikaciu
        SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());
        SSL * ssl;
        if (cfg.T_enc){
            // jedna sa o -T
            cfg.bio = set_sec_conn(ctx,false);
            BIO_get_ssl(cfg.bio, & ssl);
            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
            pop3session(true, ssl, NULL);
        }
        else {
            //jedna sa o -S
            cfg.bio = set_sec_conn(ctx,true);
            pop3session(false, ssl, ctx);
        }
        //uvolnenie dat zo struktur
        SSL_CTX_free(ctx);
    }
    else{
        //nesifrovana komunicia
        pop3session(false, NULL, NULL);
    }

    return 0;
}