[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/EbtZGzoI)
[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=23668619)

# Implementación de un Mini Cloud Log Analyzer en Bash Script + Assmblr

Alumno: Ramírez Gonzalez Benjamín

No. Control: 23212052

Materia: Lenguajes de Interfaz

---

## Implementación de un Mini Cloud Log Analyzer en ARM64

**Modalidad:** Individual
**Entorno de trabajo:** AWS Ubuntu ARM64 + GitHub Classroom
**Lenguaje:** ARM64 Assembly (GNU Assembler) + Bash + GNU Make

---

## Introducción

Los sistemas modernos de cómputo en la nube generan continuamente registros (*logs*) que permiten monitorear el estado de servicios, detectar fallas y activar alertas ante eventos críticos.

En esta práctica se desarrollará un módulo simplificado de análisis de logs, implementado en **ARM64 Assembly**, inspirado en tareas reales de monitoreo utilizadas en sistemas cloud, observabilidad y administración de infraestructura.

El programa procesará códigos de estado HTTP suministrados mediante entrada estándar (stdin):

```bash id="y1gcmc"
cat logs.txt | ./analyzer
```

---

## Objetivo general

Diseñar e implementar, en lenguaje ensamblador ARM64, una solución para procesar registros de eventos y detectar condiciones definidas según la variante asignada.

---

## Objetivos específicos

El estudiante aplicará:

* programación en ARM64 bajo Linux
* manejo de registros
* direccionamiento y acceso a memoria
* instrucciones de comparación
* estructuras iterativas en ensamblador
* saltos condicionales
* uso de syscalls Linux
* compilación con GNU Make
* control de versiones con GitHub Classroom

Estos temas se alinean con contenidos clásicos de flujo de control, herramientas GNU, manejo de datos y convenciones de programación en ensamblador.   

---

## Material proporcionado

Se entregará un repositorio preconfigurado que contiene:

* plantilla base en ARM64
* archivo `Makefile`
* script Bash de ejecución
* archivo de datos (`logs.txt`)
* pruebas iniciales
* secciones marcadas con `TODO`

El estudiante deberá completar la lógica correspondiente.

---

## Variante de la práctica

### Variante B

Determinar el código de estado más frecuente.

---

## Compilación

```bash id="bmubtb"
make
```

---

## Ejecución

```bash id="gcqlf2"
cat logs.txt | ./analyzer
```

---

## Entregables

Cada estudiante deberá entregar en su repositorio:

* archivo fuente ARM64 funcional
* solución implementada
* README explicando diseño y lógica utilizada
* evidencia de ejecución
* commits realizados en GitHub Classroom

---

## Criterios de evaluación

| Criterio                    | Ponderación |
| --------------------------- | ----------- |
| Compilación correcta        | 20%         |
| Correctitud de la solución  | 35%         |
| Uso adecuado de ARM64       | 25%         |
| Documentación y comentarios | 10%         |
| Evidencia de pruebas        | 10%         |

---

## Restricciones

No está permitido:

* resolver la lógica en C
* resolver la lógica en Python
* modificar la variante asignada
* omitir el uso de ARM64 Assembly

---

## Competencia a desarrollar

Comprender cómo un problema de procesamiento de datos es implementado a nivel máquina mediante instrucciones ARM64.

---

## Nota

Aunque este problema puede resolverse fácilmente en lenguajes de alto nivel, el propósito de la práctica es implementar **cómo lo resolvería la arquitectura**, no únicamente obtener el resultado.

---

## Evidencia de ejecución

<img width="1920" height="1080" alt="Captura de pantalla (1254)" src="https://github.com/user-attachments/assets/94013767-4e99-4b58-a69c-c0e0b4147e19" />  

\
Asciinema: https://asciinema.org/a/963564
