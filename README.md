# PROTOCOALE DE COMUNICAȚII - TEMA 4 - CLIENT WEB. COMUNICAȚIE CU REST API.

**STUDENT** - Gavrilă Paul-Alexandru

**GRUPA** - 325CC

Tema constă în implementarea unui client web care comunică cu un server prin intermediul
protocolului HTTP utilizând REST API. Implementarea mea pornește de la rezolvarea
laboratorului 9, funcțiile din cadrul acestuia fiind utilizate drept schelet.


Programul citește de la tastatură comenzi care vor fi trimise către server sub formă de request-uri, care pot fi de 3 tipuri:
- *POST REQUEST* - pentru adăugarea/trimiterea de informații către server
- *GET REQUEST* - pentru a cere și a afișa informații de pe server
- *DELETE REQUEST* - pentru a șterge informații de pe server

Funcțiile care construiesc cele 3 tipuri de request-uri se regăsesc în fișierul requests.c. Un request va conține tipul acestuia, adresa IP a server-ului, URL-ul rutei de acces, tipul de conținut al mesajului (la POST request), dar și cookie-ul de sesiune și token-ul de acces când acestea sunt necesare pentru execuția comenzii. Cookie-ul de sesiune atestă faptul că utilizatorul este înregistrat în con, iar token-ul de acces îi conferă utilizatorului acces la bibliotecă.


