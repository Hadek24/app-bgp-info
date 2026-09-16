"""
Automated Cisco BGP Configuration Extractor & Report Generator.

This script connects via SSH (using Netmiko) to Cisco IOS/IOS-XE routing devices
to extract, filter, and organize core networking configurations (Interfaces,
IP SLA, Static Routes, BGP, Route-Maps, and Prefix-Lists).

It automatically parses and categorizes policy elements (Route-Maps & Prefix-Lists)
by neighbor and traffic direction (IN/OUT) based on standardized naming conventions.

Author: Network & Security Engineering Team
License: MIT
"""

# ============================================================
# SECTION 1: Importing libraries
# ============================================================
import netmiko
import os
import re
import getpass
from datetime import datetime
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

# ============================================================
# SECTION 2: Cisco CLI Commands Execution Mapping
# ============================================================
COMANDO_HOSTNAME = "show run | i hostname"
COMANDO_CLOCK = "show clock"
COMANDO_INTERFACE = "show run | s interface"
COMANDO_IPSLA = "show run | s sla"
COMANDO_ROUTE = "show run | s route"
COMANDO_BGP = "show run | s bgp"
COMANDO_ROUTEMAP = "show run | s route-map"
COMANDO_PREFIXLIST = "show run | s prefix-list"

# ============================================================
# SECTION 3: Output Sanitation Filters
# Removes unwanted lines or generic boilerplate from CLI outputs.
# ============================================================
FILTRO_BGP = ["permit", "deny"]
FILTRO_ROUTEMAP = ["neighbor"]
FILTRO_PREFIXLIST = ["match"]
FILTRO_INTERFACE = [
    "match", "load-interval", "negotiation", "media-type",
    "source-interface", "owner", "tag", "frequency",
]
FILTRO_ROUTES = [
    "router", "network", "!", "router-id", "fast-external-fallover",
    "enforce-first-as", "log-neighbor-changes", "neighbor",
    "address-family", "exit-address-family", "route-map",
    "description", "match", "set",
]

# ============================================================
# SECTION 4: Regex Naming Standards
# Expected Conventions:
# - Route-map:   RMv4|Desde_<ORIGIN>-Hacia_<DESTINATION>
# - Prefix-list: PLv4|PL01|Desde_<ORIGIN>-Hacia_<DESTINATION>
# Direction Logic: 'RTs' indicates local router.
# - <ORIGIN> = RTs  => Traffic leaving router (OUT / Saliente)
# - <DESTINATION> = RTs => Traffic entering router (IN / Entrante)
# ============================================================
REGEX_ROUTEMAP_NOMBRE = re.compile(
    r'^RMv(?P<ver>\d+)\|Desde_(?P<origen>[^-|]+)-Hacia_(?P<destino>[^-|]+)$',
    re.IGNORECASE,
)
REGEX_PREFIXLIST_NOMBRE = re.compile(
    r'^PLv(?P<ver>\d+)\|PL(?P<plnum>\d+)\|Desde_(?P<origen>[^-|]+)-Hacia_(?P<destino>[^-|]+)$',
    re.IGNORECASE,
)

def extraer_vecino_y_direccion(nombre: str, regex: re.Pattern) -> Optional[Tuple[str, str, str]]:
    """Extracts neighbor, direction (IN/OUT), and IP version from policy names.

    Args:
        nombre (str): Name of the Route-Map or Prefix-List object.
        regex (re.Pattern): Compiled regex object matching standard naming.

    Returns:
        Optional[Tuple[str, str, str]]: Tuple containing (neighbor_name, direction, ip_version)
                                        or None if name does not fit convention."""
    m = regex.match(nombre)
    if not m:
        return None

    origen = m.group("origen")
    destino = m.group("destino")
    version = m.group("ver")

    if destino.upper() == "RTS":
        return origen, "IN", version
    elif origen.upper() == "RTS":
        return destino, "OUT", version
    else:
        return None

# ============================================================
# SECTION 5: Network Communication & SSH Management
# ============================================================
def mostrar_bienvenida() -> None:
    """Displays CLI welcome banner and summary of operations."""
    print("""
    ****************************************************************
    *                                                              *
    *    Bienvenido al programa de recopilacion de informacion     *
    *                    para analisis de BGP.                     *
    *                                                              *
    ****************************************************************
    *                                                              *
    *      El script ejecutara los siguientes comandos:            *
    *                                                              *
    *         - Show running-config | i Hostname                   *
    *         - Show clock                                         *
    *         - Show running-config | S Interface                  *
    *         - Show running-config | S SLA                        *
    *         - Show running-config | i Route                      *
    *         - Show running-config | i BGP                        *
    *         - Show running-config | i Route-Map                  *
    *         - Show running-config | i Prefix-List                *
    *                                                              *
    ****************************************************************
    *                                                              *
    *   Advertencia: Tanto el uso de este script como el acceso    *
    *    a los equipos, estan restringidos a personal del area     *
    *   Seguridad y Networking.                                    *
    *                                                              *
    ****************************************************************
    """)

def pedir_credenciales() -> Dict[str, str]:
    """Prompts operator for SSH target host and authentication details."""
    device_type = input("- Ingresar el tipo de equipo (ej. cisco_ios): ").strip()
    ip = input("\n- Ingresar la direccion IP del equipo: ").strip()
    username = input("\n- Ingresar el usuario para la conexion: ").strip()
    password = getpass.getpass("\n- Ingrese la contraseña para la conexion: ")

    return {
        "device_type": device_type,
        "ip": ip,
        "username": username,
        "password": password,
    }

def conectar_dispositivo(dispositivo: Dict[str, str]) -> Optional[netmiko.BaseConnection]:
    """Establishes Netmiko SSH connection handling basic authentication errors."""
    try:
        net_connect = netmiko.ConnectHandler(**dispositivo)
        return net_connect
    except netmiko.NetMikoAuthenticationException as e:
        print(f"\nError de autenticación: {e}")
        print("\nVerifique que el nombre de usuario y la contraseña sean correctos.\n")
    except netmiko.NetMikoTimeoutException as e:
        print(f"\nError de tiempo de espera: {e}")
        print("\nVerifique que el dispositivo esté encendido y que la conexión de red sea estable.\n")
    except Exception as e:
        print(f"\nError desconocido: {e}")
        print("\nVerifique que la dirección IP y el nombre de usuario sean correctos.\n")
    return None

def ejecutar_comando(net_connect: netmiko.BaseConnection, comando: str) -> str:
    """Executes CLI command via SSH handler and captures output safely."""
    try:
        return net_connect.send_command(comando)
    except Exception as e:
        print(f"\nError al ejecutar el comando '{comando}': {e}")
        return ""

def filtrar_salida(salida: str, opciones_filtrado: List[str]) -> List[str]:
    """Filters unwanted keywords out of CLI text output lines."""
    if not salida:
        return []
    return [
        line for line in salida.splitlines()
        if not any(palabra in line for palabra in opciones_filtrado)
    ]

def obtener_lineas(salida: str) -> List[str]:
    """Splits raw string command output into lines list."""
    return salida.splitlines() if salida else []

def conectar_con_reintentos(dispositivo: Dict[str, str]) -> Tuple[netmiko.BaseConnection, Dict[str, str]]:
    """Handles connection retry loop with credential adjustment options."""
    while True:
        print("\n" + "*" * 64)
        print("\nIntentando conectar al dispositivo, favor de esperar...\n")
        net_connect = conectar_dispositivo(dispositivo)

        if net_connect is not None:
            print("\nLa conexión al dispositivo ha sido exitosa.\n")
            return net_connect, dispositivo

        respuesta = input(
            "\nLa conexion al dispositivo ha fallado. ¿Desea intentar nuevamente? (s/n): "
        ).strip().lower()

        if respuesta == "n":
            print("\nMuchas gracias por utilizar el programa, revise la información y vuelva a intentarlo.")
            exit()

        if respuesta != "s":
            print("\nOpción ingresada inválida. Se interpreta como 'no'.")
            exit()

        opcion = input(
            "\nA continuación elija una opción:\n"
            " 1. Volver a reintentar con los datos ingresados.\n"
            " 2. Probar con nuevos datos.\n"
            " 3. Salir.\n\n Opcion: "
        ).strip()

        if opcion == "2":
            dispositivo = pedir_credenciales()
        elif opcion == "3":
            print("\nGracias por utilizar el programa. ¡Hasta luego!")
            exit()

# ============================================================
# SECTION 6: Data Parsing & Grouping Algorithms
# ============================================================
def dividir_en_bloques_routemap(lineas_filtradas: List[str]) -> List[List[str]]:
    """Groups CLI route-map lines into block lists based on 'route-map' headers."""
    bloques = []
    bloque_actual = []

    for linea in lineas_filtradas:
        if linea.strip().startswith("route-map "):
            if bloque_actual:
                bloques.append(bloque_actual)
            bloque_actual = [linea]
        elif bloque_actual:
            bloque_actual.append(linea)

    if bloque_actual:
        bloques.append(bloque_actual)

    return bloques

# ============================================================
# SECCION 7a: Grouping of route map by neighbor
# ============================================================
def agrupar_route_maps(lineas_filtradas: List[str]) -> List[str]:
    """Groups Route-Maps by neighbor (IN/OUT direction) or 'Unmatched' section."""
    bloques = dividir_en_bloques_routemap(lineas_filtradas)

    grupos = OrderedDict()   # vecino -> {"IN": [bloques], "OUT": [bloques]}
    sin_agrupar = []

    for bloque in bloques:
        primera_linea = bloque[0].strip()
        partes = primera_linea.split()
        nombre = partes[1] if len(partes) > 1 else ""

        resultado = extraer_vecino_y_direccion(nombre, REGEX_ROUTEMAP_NOMBRE)
        if resultado is None:
            sin_agrupar.append(bloque)
            continue

        vecino, direccion, version = resultado
        clave = f"{vecino} (IPv{version})"
        grupos.setdefault(clave, {"IN": [], "OUT": []})
        grupos[clave][direccion].append(bloque)

    lineas_salida = []
    for vecino, direcciones in grupos.items():
        lineas_salida.append(f"### Vecino: {vecino} ###")
        for direccion in ("IN", "OUT"):
            for bloque in direcciones[direccion]:
                lineas_salida.extend(bloque)
                lineas_salida.append("")
        lineas_salida.append("")

    if sin_agrupar:
        lineas_salida.append("### Sin agrupar automáticamente ###")
        for bloque in sin_agrupar:
            lineas_salida.extend(bloque)
            lineas_salida.append("")

    return lineas_salida

# ============================================================
# SECCION 7b: Grouping of prefix lists by neighbor
# ============================================================
def agrupar_prefix_lists(lineas_filtradas: List[str]) -> List[str]:
    """Groups Prefix-Lists by neighbor and sub-labels them by policy number."""
    grupos = OrderedDict()   # vecino -> {"PL01 - IN": [lineas], ...}
    sin_agrupar = []

    patron_nombre = re.compile(r'prefix-list (\S+) seq', re.IGNORECASE)

    for linea in lineas_filtradas:
        m = patron_nombre.search(linea)
        if not m:
            sin_agrupar.append(linea)
            continue

        nombre = m.group(1)
        resultado = extraer_vecino_y_direccion(nombre, REGEX_PREFIXLIST_NOMBRE)
        if resultado is None:
            sin_agrupar.append(linea)
            continue

        vecino, direccion, version = resultado
        m2 = REGEX_PREFIXLIST_NOMBRE.match(nombre)
        plnum = m2.group("plnum")

        clave_vecino = f"{vecino} (IPv{version})"
        etiqueta = f"PL{plnum} - {'Entrante (Desde vecino)' if direccion == 'IN' else 'Saliente (Hacia vecino)'}"

        grupos.setdefault(clave_vecino, OrderedDict())
        grupos[clave_vecino].setdefault(etiqueta, [])
        grupos[clave_vecino][etiqueta].append(linea)

    lineas_salida = []
    for vecino, subgrupos in grupos.items():
        lineas_salida.append(f"### Vecino: {vecino} ###")
        for etiqueta, lineas_pl in sorted(subgrupos.items()):
            lineas_salida.append(f"  [{etiqueta}]")
            lineas_salida.extend(lineas_pl)
            lineas_salida.append("")
        lineas_salida.append("")

    if sin_agrupar:
        lineas_salida.append("### Sin agrupar automáticamente ###")
        lineas_salida.extend(sin_agrupar)

    return lineas_salida

# ============================================================
# SECTION 8: File I/O Output Generation
# ============================================================
def guardar_reporte(hostname: str, secciones: List[Tuple[str, List[str]]]) -> str:
    """Exports structured configuration sections to a timestamped text report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{hostname}_{timestamp}.txt"

    with open(filename, "w") as archivo:
        for titulo, lineas in secciones:
            archivo.write("=" * 65 + f"\nSeccion {titulo}:\n" + "=" * 65 + "\n\n")
            for line in lineas:
                archivo.write(line + "\n")
            archivo.write("\n")

    return filename

# ============================================================
# SECTION 9: Execution Controller / Main Entry Point
# ============================================================
def main() -> None:
    mostrar_bienvenida()

    dispositivo = pedir_credenciales()
    net_connect, dispositivo = conectar_con_reintentos(dispositivo)

    # --- Ejecución de comandos ---
    print("\nEjecutando comandos...\n")
    hostname_output = ejecutar_comando(net_connect, COMANDO_HOSTNAME)
    clock_output = ejecutar_comando(net_connect, COMANDO_CLOCK)
    interface_output = ejecutar_comando(net_connect, COMANDO_INTERFACE)
    ipsla_output = ejecutar_comando(net_connect, COMANDO_IPSLA)
    route_output = ejecutar_comando(net_connect, COMANDO_ROUTE)
    bgp_output = ejecutar_comando(net_connect, COMANDO_BGP)
    routemap_output = ejecutar_comando(net_connect, COMANDO_ROUTEMAP)
    prefixlist_output = ejecutar_comando(net_connect, COMANDO_PREFIXLIST)

    net_connect.disconnect()
    print("\nConexión cerrada.")

    # Apply configuration line filtering
    interface_config = filtrar_salida(interface_output, FILTRO_INTERFACE)
    route_config = filtrar_salida(route_output, FILTRO_ROUTES)
    bgp_config = filtrar_salida(bgp_output, FILTRO_BGP)
    routemap_config = filtrar_salida(routemap_output, FILTRO_ROUTEMAP)
    prefixlist_config = filtrar_salida(prefixlist_output, FILTRO_PREFIXLIST)
    ipsla_config = obtener_lineas(ipsla_output)

    # Process policies by direction & neighbor
    routemap_agrupado = agrupar_route_maps(routemap_config)
    prefixlist_agrupado = agrupar_prefix_lists(prefixlist_config)

    # --- Nombre de archivo ---
    if hostname_output:
        hostname = hostname_output.split()[-1]
    else:
        hostname = "equipo_desconocido"

    # Assemble output sections
    secciones = [
        ("Interfaces", interface_config),
        ("IP SLA", ipsla_config),
        ("Static Routes", route_config),
        ("BGP", bgp_config),
        ("Route-Map (agrupado por vecino)", routemap_agrupado),
        ("Prefix-List (agrupado por vecino)", prefixlist_agrupado),
    ]

    print("\nGuardando comandos aplicados en un archivo de texto...")
    filename = guardar_reporte(hostname, secciones)

    print("\nSalida guardada correctamente en archivo de texto.")
    print(f"El archivo posee el siguiente nombre: {filename}")
    print("El archivo fue creado en la siguiente ubicacion:", os.getcwd())
    print("\nGracias por utilizar el programa. ¡Hasta luego!\n")

if __name__ == "__main__":
    main()
