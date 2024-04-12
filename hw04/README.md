Vaším úkolem je realizovat dvě funkce (seal a open), které šifrují/dešifrují data pomocí hybridního šifrování.

Parametry Vámi implementované funkce seal:

bool seal(string_view inFile, string_view outFile, string_view publicKeyFile, string_view symmetricCipher)

    inFile - soubor, který obsahuje binární data určená k zašifrování,
    outFile - výstupní soubor, kam uložíte všechny potřebné údaje k dešifrování,
    publicKeyFile - veřejný klíč, který bude použit k zašifrování symetrického klíče,
    symmetricCipher - název symetrické šifry použité pro šifrování,
    návratová hodnota je true v případě úspěchu, false v opačném případě. Pokud funkce selže, musíte zaručit, že výstupní soubor outFile nebude existovat.

Funkce vygeneruje symetrický (sdílený) klíč a inicializační vektor (dále IV), který bude vstupem do symetrické šifry symmetricCipher. Touto šifrou, klíčem a IV zašifrujete data v inFile. Klíč k symetrické šifře zašifrujete asymetrickou šifrou (RSA) pomocí veřejného klíče uloženého v publicKeyFile.

OpenSSL udělá většinu práce za vás:

    PEM_read_PUBKEY - načte veřejný klíč,
    EVP_SealInit - vygeneruje sdílený klíč a IV (pokud je potřeba), zašifruje sdílený klíč a nastaví kontext,
    EVP_SealUpdate a EVP_SealFinal fungují stejně jako v předchozích úkolech.

Hybridní šifrování počítá s šifrováním pro více adresátů. Data jsou zašifrována jen jednou, jedním sdíleným klíčem a IV, ale sdílený klíč může být zašifrován více veřejnými klíči. Proto funkce přijímá pole veřejných klíčů.

Výstupní soubor bude mít následující strukturu:
Pozice v souboru 	Délka 	Struktura 	Popis
0 	4 B 	int 	NID - numerical identifier for an OpenSSL cipher. (Použitá symetrická šifra)
4 	4 B 	int 	EKlen - délka zašifrovaného klíče
8 	EKlen B 	pole unsigned char 	Zašifrovaný klíč pomocí RSA
8 + EKlen 	IVlen B 	pole unsigned char 	Inicializační vektor (pokud je potřeba)
8 + EKlen + IVlen 	— 	pole unsigned char 	Zašifrovaná data

Parametry Vámi implementované funkce open:

bool open(string_view inFile, string_view outFile, string_view privateKeyFile)

    inFile - zašifrovaný soubor ve stejném formátu jako je výstupní soubor z funkce seal,
    outFile - výstupní soubor, kam uložíte všechna dešifrovaná data (je očekávána binární shoda se vstupním souborem do seal funkce),
    privateKeyFile - privátní klíč určený pro dešifrování zašifrovaného klíče,
    návratová hodnota je true v případě úspěchu, false v opačném případě. Pokud funkce selže, musíte zaručit, že výstupní soubor outFile nebude existovat.

V této funkci budou hlavní roli hrát funkce PEM_read_PrivateKey, EVP_OpenInit, EVP_OpenUpdate a EVP_OpenFinal.

Obsah ukázkových dat:

    PublicKey.pem - veřejný klíč (schválně ho zkuste otevřít jako txt),
    PrivateKey.pem - privátní klíč,
    sample.cpp - soubor s deklaracemi a základním testem,
    sealed_sample.bin - zašifrovaný soubor, na kterém můžete testovat dešifrování. Byl zašifrován přiloženým veřejným klíčem a po dešifrování v něm naleznete ASCII text. Pokud zašifrujete stejná data, pak soubor nebude stejný jako sealed_sample.bin - byl použit jiný klíč a IV.
