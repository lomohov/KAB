Vaším úkolem je realizovat funkci (či sadu funkcí, ne celý program), které naleznou libovolnou zprávu, jejíž hash (SHA-512) začíná zleva na posloupnost nulových bitů.

Pořadí bitů je big-endian: Bajt 0 od MSB do LSB, Bajt 1 od MSB do LSB, …, poslední bajt od MSB do LSB.

Neboli, dva nulové bity odpovídají například bajtu 0010 0111 (0x27).

Funkce je požadována ve dvou variantách:

    základní řešení (funkce findHash). Implementace této funkce je povinná.
    vylepšené řešení (funkce findHashEx). Implementace této funkce není povinná, bez dodané „dummy“ implementace se ale úloha nepodaří zkompilovat. Funkci implementujte, pokud se rozhodnete usilovat o bonus.

Parametry Vámi implementovaných funkcí jsou:

int findHash (int bits, string & message, string & hash)

    bits - požadovaný počet nulových bitů v hashi zprávy.
    message - výstupní parametr. Tento parametr obsahuje data, pro která byl nalezen příslušný hash. Výsledek je uložen jako hexadecimální řetězec.
    hash - výstupní parametr. Jedná se o hash zprávy message z předchozího parametru, opět jde o hexadecimální řetězec.
    Návratovou hodnotou funkce je 1 v případě úspěchu, 0 v případě neúspěchu nebo nesprávných parametrů. Těmi je typicky požadovaný počet nulových bitů, který nedává smysl.

int findHashEx (int bits, string & message, string & hash, string_view hashFunction)

    rozšíření funkce findHash. Všechny parametry i návratová hodnota zůstavají stejné jako v případě základní varianty.
    hashFunction - nový parametr, který udává, která hashovací funkce má být použita pro nalezení posloupnosti nulových bitů. Zadaný název hashovací funkce je kompatibilní s funkcí EVP_get_digestbyname.

Odevzdávejte zdrojový soubor, který obsahuje implementaci požadované funkce findHash, resp. findHashEx. Do zdrojového souboru si můžete přidat i další Vaše podpůrné funkce, které jsou z findHash (resp. findHashEx) volané. Funkce bude volána z testovacího prostředí, je proto důležité přesně dodržet zadané rozhraní funkce.

Za základ pro implementaci použijte kód z přiloženého archivu níže. Ukázka obsahuje testovací funkci main, uvedené hodnoty jsou použité při základním testu. Všimněte si, že vkládání hlavičkových souborů a funkce main jsou zabalené v bloku podmíněného překladu (#ifdef/#endif). Prosím, ponechte bloky podmíněného překladu i v odevzdávaném zdrojovém souboru. Podmíněný překlad Vám zjednoduší práci. Při kompilaci na Vašem počítači můžete program normálně spouštět a testovat. Při kompilaci na Progtestu funkce main a vkládání hlavičkových souborů „zmizí“, tedy nebude kolidovat s hlavičkovými soubory a funkcí main testovacího prostředí.

V ukázce se dále nachází funkce dumpMatch, kterou si budete (s nemalou pravděpodobností) muset implementovat pro své lokální testování. Funkce je zabalená v bloku podmíněného překladu (=nebude testována). Přesto je vhodné ji implementovat pro ověření správnosti Vašeho řešení.