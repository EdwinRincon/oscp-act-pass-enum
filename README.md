# OSINT Enum

Herramienta de línea de comandos en Python para practicar enumeración pasiva y activa de dominios. Incluye también un comprobador de cabeceras de seguridad HTTP y un servidor HTTP local que muestra y registra la cabecera `User-Agent` recibida. Se añade una interfaz web local como alternativa para ejecutar enumeraciones.

Este proyecto se ha desarrollado para cubrir la tarea de clase: realizar enumeración pasiva y activa, consultar las cabeceras de seguridad de un sitio y crear un servidor que capture el `User-Agent` de las peticiones.

## Instalación

Ejecuta estos comandos desde la carpeta del proyecto:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Activa el entorno virtual cada vez que abras una terminal nueva antes de usar los scripts. En Windows, la activación se realiza con `.venv\Scripts\activate`.

## Enumeración de dominios

La enumeración pasiva es el modo predeterminado. Consulta fuentes públicas de terceros y no envía solicitudes directamente al dominio objetivo:

```bash
python enum_tool.py -d example.com
```

Para ejecutar módulos activos, que consultan directamente el dominio, confirma que tienes autorización:

```bash
python enum_tool.py -d example.com -m active --i-have-permission
```

También se pueden combinar ambos tipos de módulos y generar informes JSON y HTML. Los informes se guardan en `output/` de forma predeterminada:

```bash
python enum_tool.py -d example.com -m all --i-have-permission --json --html
```

Para consultar los módulos disponibles o limitar cuáles se ejecutan:

```bash
python enum_tool.py --list-modules
python enum_tool.py -d example.com --only whois,crtsh
```

`--only` acepta identificadores separados por comas y selecciona esos módulos. Usa `--exclude` para omitir módulos concretos. Si la selección incluye módulos activos, también se requiere `--i-have-permission`.

### Opciones HTTP

Las peticiones HTTP usan por defecto un timeout de 10 segundos y un User-Agent
predeterminado. `--timeout` configura el timeout de todas las peticiones y acepta valores de
3 a 30 segundos. Puedes personalizar el User-Agent (hasta 512 caracteres) y añadir hasta
40 cabeceras con `--header` (repetible):

```bash
python enum_tool.py -d example.com --user-agent "OSCP-lab/1.0" \
  --header "X-Engagement: LAB-42" --timeout 15
```

La interfaz web ofrece los mismos ajustes en **Advanced**. Las cabeceras personalizadas se
escriben una por línea como `Nombre: valor`; cada valor puede tener hasta 4096 caracteres y
el total de nombres y valores no puede superar 8192 caracteres. Por seguridad, no se pueden reemplazar
`Host`, `Content-Length`, `Transfer-Encoding`, `Connection` ni `User-Agent`; este último se
configura en su campo específico. Los informes registran el User-Agent y los nombres de las
cabeceras personalizadas, pero no sus valores.

## Comprobar cabeceras de seguridad

El script realiza una petición HTTP y muestra si están presentes varias cabeceras de seguridad, además de señalar algunas cabeceras que pueden revelar información del servidor. Si no se especifica el protocolo, se usa HTTPS:

```bash
python headers_check.py https://example.com
```

## Capturar la cabecera User-Agent

Abre dos terminales con el entorno virtual activado. En la primera, inicia el servidor local:

```bash
python ua_server.py --port 8080
```

En la segunda, realiza una petición al servidor con el comprobador de cabeceras:

```bash
python headers_check.py http://127.0.0.1:8080
```

El servidor muestra el `User-Agent` en la primera terminal y lo añade a `output/user_agents.log`. Detén el servidor con `Ctrl+C`.

## Interfaz web (opcional)

Para abrir la interfaz local, ejecuta:

```bash
python web_server.py
```

Visita <http://127.0.0.1:8000>. La interfaz no tiene autenticación; mantenla en una dirección local y no la expongas a una red pública.

### Captura de la interfaz web

La siguiente captura muestra la interfaz con un resultado real:

![Captura de la interfaz web con un resultado real](docs/images/web-result.png)

## Uso responsable

Ejecuta módulos activos únicamente sobre dominios propios o para los que tengas autorización explícita. Las consultas activas contactan directamente con el objetivo y pueden quedar registradas por este.
