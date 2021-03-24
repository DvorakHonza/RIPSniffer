# Nástroje monitorující a generující zprávy jednoduchých distance-vector protokolů

Projekt vznikl v rámci předmětu Síťové aplikace se skládá ze sady
nástrojů pro odchytávání RIPv1, RIPv2 a RIPng paketů, dále pak vytváření
a podvrhování RIPng response a request zpráv.

Použití:

* Přepínače v {} jsou volitelné.

```bash
myripsniffer:

    sudo ./myripsniffer {-h} -i <interface>

    -h vytiskne nápovědu
    -i <interface> rozhraní, na kterém se bude RIP komunikace odpo-
        slouchávat

myripresponse:

    sudo ./myripresponse {-h} -i <interface> -r <IPv6>/[16-128] {-n <IPv6>}
                            {-m [0-16]} {-t [0-65535]}

    -h vytiskne nápovědu
    -i <interface> rozhraní, ze kterého bude útočný paket odeslán
    -r <IPv6/[16 -128]> IPv6 adresa s délkou prefixu sítě, kterou chceme pod-
        vrhnout směrovači
    -n <IPv6> IPv6 next hop adresa pro podvrhovanou síť, aby byla vložena do 
        směrovací tabulky musí to být link-local adresa
    -m [0-16] metrika podvrhávané sítě
    -t [0-65535] route tag

myriprequest:

    sudo ./myriprequest {-h} -i <interface> [-a|-r <IPv6/[16-128]]

    -i <interface> rozhraní, ze kterého bude request paket odeslán
    -a žádost o celou routovací tabulku
    -r <IPv6/[16-128]> adresa sítě, pro kterou žádáme záznamy ze směrovací ta-
        bulky           
```
