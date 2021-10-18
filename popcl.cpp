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


class MyException {
public:
  std::string str_what;

  MyException() { str_what = ""; }

  MyException(std::string s) {
     str_what = s;
   }
};



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

bool cmdOptionExists(char** begin, char** end, const std::string& option){
    return std::find(begin, end, option) != end;
}

void parse_arguments(int argc, char **argv){
    if (argc < 6){
        fprintf(stderr, "%s", usage);
        exit(1);
    }

    cfg.server = std::string(argv[1]);
    std::cout << cfg.server << std::endl;

    char * auth_f = getCmdOption(argv, argv + argc, "-a", true);
    if (auth_f){
        printf("auth file -> %s\n", auth_f);
        FILE *file;
        if ((file = fopen(auth_f, "r"))) {
            fclose(file);
        } 
        else {
            printf("Konfiguracni soubor s autentizacnimi udajmi neexistuje\n");
            exit(1);
        }
        std::string myText;

        std::ifstream MyReadFile(auth_f);

        int line_n = 0;
        std::regex un("^(username = )([^\\s]+)$");
        std::regex pw("^(password = )([^\\s]+)$");
        std::smatch match;
        while (getline (MyReadFile, myText)) {
            line_n++;
            if (line_n == 1){
                if (!std::regex_match(myText, un)){
                    printf("Zly konfiguracni soubor\n");
                    exit(1);
                }
                regex_search(myText, match, un);
                cfg.username = match.str(2);
            }
            else if (line_n == 2){
                if (!std::regex_match(myText, pw)){
                    printf("Zly konfiguracni soubor\n");
                    exit(1);
                }
                regex_search(myText, match, pw);
                cfg.password = match.str(2);
            }
            else {
                printf("Zly konfiguracni soubor\n");
                exit(1);
            }
        }
        MyReadFile.close();
    }

    char * outdir = getCmdOption(argv, argv + argc, "-o", true);
    if (outdir){
        printf("outdir -> %s\n", outdir);
        if(!std::filesystem::is_directory(std::filesystem::status(outdir))){
            fprintf(stderr, "Zadany adresar pre emaily neexistuje\n");
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

    // if(cmdOptionExists(argv, argv + argc, "-p")){
    //     char * port = getCmdOption(argv, argv + argc, "-p", false);
    //     if (port){
    //         printf("port -> %s\n", port);
    //         try {
    //             // nastavenia cisla portu ak bolo zadane
    //             cfg.port = std::stoi(std::string(port));
    //             if (cfg.port < 0 || cfg.port >  65535) {
    //                 fprintf(stderr, "Cislo portu je zle zadane\n");
    //                 exit(1);
    //             }
    //         } catch (std::exception const&) {
    //             fprintf(stderr, "Cislo portu je zle zadane\n");
    //             exit(1);
    //         }
    //     }
    // }
    

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
            printf("certfile -> %s\n", certf);

            FILE *cfile;
            if ((cfile = fopen(certf, "r"))) {
                fclose(cfile);
            } 
            else {
                printf("Subor s certifikaty neexistuje\n");
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
        if (certdir){
            printf("certdir -> %s\n", certdir);
            if(!std::filesystem::is_directory(std::filesystem::status(certdir))){
                fprintf(stderr, "Zadany adresar s certifikaty neexistuje\n");
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
            printf("port -> %s\n", port);
            try {
                // nastavenia cisla portu ak bolo zadane
                cfg.port = std::stoi(std::string(port));
                if (cfg.port < 0 || cfg.port >  65535) {
                    fprintf(stderr, "Cislo portu je zle zadane\n");
                    exit(1);
                }
            } catch (std::exception const&) {
                fprintf(stderr, "Cislo portu je zle zadane\n");
                exit(1);
            }
        }
    }

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

std::string get_response(){
    int len = 1024;
    char buf[len];
    std::fill_n(buf, len, 0);

    int x = BIO_read(cfg.bio, buf, len);
    if(x == 0){
        throw MyException ("Spojenie bolo ukoncene (chyba v komunikacii)\n");
    }
    else if(x < 0){
        throw MyException ("Nastala chyba pri komunikacii so serverom\n");
    }

    if (buf[0] == '-'){
        throw MyException("Server nedokazal odpovedat na poziadavok\n");
    }

    return std::string(buf);
}

void send_command(std::string command){
    command = command + "\r\n";
    char* c_command = const_cast<char*>(command.c_str());
    int code = BIO_puts(cfg.bio, c_command);

    if(code == 0){
        throw MyException("Spojenie bolo ukoncene (chyba v komunikacii)\n");
    }
    else if(code < 0){
        throw MyException ("Nastala chyba pri komunikacii so serverom\n");
    }
}

BIO *create_connection(std::string server, int port){
    std::string hostname = server + ":"+std::to_string(port);
    char* host_name = const_cast<char*>(hostname.c_str());

    BIO *new_bio = BIO_new_connect(host_name);
    if(new_bio == NULL){
        fprintf(stderr, "Chyba pri vytvarani spojenia\n");
        exit(1);
    }

    if(BIO_do_connect(new_bio) <= 0){
        fprintf(stderr, "Nepodarilo sa pripojit k serveru\n");
        exit(1);
    }

    return new_bio;
}

void create_sec_connection(BIO * bio, std::string server, int port){
    std::string hostname = server + ":"+std::to_string(port);
    char* host_name = const_cast<char*>(hostname.c_str());

    BIO_set_conn_hostname(bio, host_name);

    if(BIO_do_connect(bio) <= 0){
        fprintf(stderr, "Nepodarilo sa pripojit k serveru(SSL)\n");
        exit(1);
    }
}

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

void save_email(std::string email, std::string filename){
    std::ofstream MyFile(cfg.outdir + filename);
    MyFile << email;
    MyFile.close();

}

std::string download_email(BIO * bio, int i){
    send_command("RETR " + std::to_string(i));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    std::string resp = "";
    
    unsigned int len = 1024;
    char buf[len];
    bool first_read = true;

    while (true){
        std::fill_n(buf, len, 0);
        int x = BIO_read(cfg.bio, buf, len);
        if(x == 0){
            throw MyException ("Spojenie bolo ukoncene (chyba v komunikacii)\n");
        }
        else if(x < 0){
            throw MyException ("Nastala chyba pri komunikacii so serverom\n");
        }

        if (buf[0] == '-' && first_read){
            throw MyException("Server nedokazal odpovedat na poziadavok\n");
        }
        first_read = false;

        std::string tmp_resp = std::string (buf);
        if (tmp_resp.length() > len){
            tmp_resp.erase(tmp_resp.end() - (tmp_resp.length() - len), tmp_resp.end());
        }
        resp = resp + tmp_resp;
        if (resp.find("\r\n.\r\n") != std::string::npos){
            break;
        }
    }
    resp.erase(resp.length()-3, resp.length());
    resp.erase(0, resp.find("\r\n") + 2);
    return resp;
}

void download_all_emails(BIO *bio, bool new_mails){
    //pocet emailov
    send_command("STAT");
    std::string resp;
    try {
        resp = get_response();
    }
    catch (MyException e){
        std::cerr << e.str_what;
        exit(1);
    }

    std::regex nom("^(\\+OK )(\\d+)");
    std::smatch match;
    regex_search(resp, match, nom);
    int n_emails = std::stoi(match.str(2));

    std::string email;
    int c_nm = 0;

    for (int i = 1; i <= n_emails; i++){
        try {
            email = download_email(bio, i);
        }
        catch (MyException e){
            std::cerr << e.str_what;
            exit(1);
        }
        // vypisat kolko emailov sa stiahlo ak to zliha pri stahovani
        // ked zada adresar bez / na konci FIX

        std::regex mid("([Mm][Ee][Ss][Ss][Aa][Gg][Ee]-[Ii][Dd]: )(.+)");
        std::smatch mat;
        regex_search(email, mat, mid);

        if (new_mails){
            std::ifstream ifile;
            ifile.open(cfg.outdir + mat.str(2));
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
    if (new_mails){
        std::cout << "Staženy " + std::to_string(c_nm) + " nových zpráv\n";
    }else {
        std::cout << "Staženy " + std::to_string(n_emails) + " zprávy\n";
    }

}

void delete_emails(BIO *bio){
    send_command("STAT");
    std::string resp;
    try {
        resp = get_response();
    }
    catch (MyException e){
        std::cerr << e.str_what;
        exit(1);
    }

    std::regex nom("^(\\+OK )(\\d+)");
    std::smatch match;
    regex_search(resp, match, nom);
    int n_emails = std::stoi(match.str(2));

    for (int i = 1; i <= n_emails; i++){
        send_command("DELE " + std::to_string(i));
        try {
            resp = get_response();
        }
        catch (MyException e){
            std::cerr << e.str_what;
            exit(1);
        }
        std::cout << resp << std::endl;
    }
    std::cout << "Zmazaných " + std::to_string(n_emails) + " zpráv\n";
}




void pop3session(bool secure, SSL * ssl){

    std::string resp;

    if (secure){
        create_sec_connection(cfg.bio, cfg.server, cfg.port);
        try {
            resp = get_response();
        }
        catch (MyException e){
            std::cerr << e.str_what;
            exit(1);
        }

        if(SSL_get_verify_result(ssl) != X509_V_OK){
            fprintf(stderr, "Nepodarilo sa overit certifikat\n");
            exit(1);
        }
    }
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

    authentificate(cfg.username, cfg.password);

    if (cfg.del_mails){
        delete_emails(cfg.bio);
    }
    else if (cfg.new_mails){
        download_all_emails(cfg.bio, true);
    }
    else {
        download_all_emails(cfg.bio, false);
    }


    //quit
    send_command("QUIT");
    try {
        resp = get_response();
    }
    catch (MyException e){
        std::cerr << e.str_what;
        exit(1);
    }

    
    BIO_free_all(cfg.bio);
}

BIO * set_sec_conn(SSL_CTX * ctx){
    if (!cfg.certfile.empty()){
            char* path = const_cast<char*>(cfg.certfile.c_str());
            if(! SSL_CTX_load_verify_locations(ctx, path, NULL)){
                std::cerr << "Nepodarilo sa nacitat certifikat" << std::endl;
                exit(1);
            }
        }

        if (!cfg.certdir.empty()){
            char* path = const_cast<char*>(cfg.certdir.c_str());
            if(! SSL_CTX_load_verify_locations(ctx, NULL, path)){
                std::cerr << "Nepodarilo sa nacitat adresar s certifikaty" << std::endl;
                exit(1);
            }
        }

        if (cfg.certfile.empty() && cfg.certdir.empty()){
            SSL_CTX_set_default_verify_paths(ctx);
        }

        BIO * bio = BIO_new_ssl_connect(ctx);
        return bio;
}


int main(int argc, char **argv){

    parse_arguments(argc, argv);

    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if (cfg.T_enc){
        SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());
        SSL * ssl;
        cfg.bio = set_sec_conn(ctx);
        BIO_get_ssl(cfg.bio, & ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        pop3session(true, ssl);

        SSL_CTX_free(ctx);
    }
    else{
        pop3session(false, NULL);
    }

    return 0;
}