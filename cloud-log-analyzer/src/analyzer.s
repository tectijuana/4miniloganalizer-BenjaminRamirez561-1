/*
Autor: Equipo docente (base para estudiantes)
Curso: Arquitectura de Computadoras / Ensamblador ARM64
Práctica: Mini Cloud Log Analyzer (Bash + ARM64 + GNU Make)
Fecha: 20 de abril de 2026
Descripción: Lee códigos HTTP desde stdin (uno por línea), clasifica 2xx/4xx/5xx
             y muestra un reporte en español usando únicamente syscalls Linux.
*/

/*
PSEUDOCÓDIGO (guía didáctica)
1) Inicializar contadores en 0: exitos_2xx, errores_4xx, errores_5xx.
2) Mientras haya bytes por leer en stdin:
   2.1) Leer un bloque con syscall read.
   2.2) Recorrer byte por byte.
   2.3) Si el byte es dígito, acumular numero_actual = numero_actual * 10 + dígito.
   2.4) Si el byte es '\n', clasificar numero_actual y reiniciar acumulador.
3) Si el flujo termina sin '\n' final y hay número pendiente, clasificarlo.
4) Imprimir resultados en español con syscall write.
5) Salir con código 0.

TODO (extensión para estudiantes):
- Agregar manejo de códigos no válidos y contarlos.
- Implementar variantes B, C, D y E en ramas separadas.
- Mostrar porcentaje de éxito respecto al total.
*/

/*
.equ SYS_read,   63
.equ SYS_write,  64
.equ SYS_exit,   93
.equ STDIN_FD,    0
.equ STDOUT_FD,   1

.section .bss
    .align 4
buffer:         .skip 4096
num_buf:        .skip 32      // Buffer para imprimir enteros en texto

.section .data
msg_titulo:         .asciz "=== Mini Cloud Log Analyzer ===\n"
msg_2xx:            .asciz "Éxitos 2xx: "
msg_4xx:            .asciz "Errores 4xx: "
msg_5xx:            .asciz "Errores 5xx: "
msg_fin_linea:      .asciz "\n"

.section .text
.global _start

_start:
    // Contadores principales
    mov x19, #0                  // exitos_2xx
    mov x20, #0                  // errores_4xx
    mov x21, #0                  // errores_5xx

    // Estado del parser
    mov x22, #0                  // numero_actual
    mov x23, #0                  // tiene_digitos (0/1)

leer_bloque:
    // read(STDIN_FD, buffer, 4096)
    mov x0, #STDIN_FD
    adrp x1, buffer
    add x1, x1, :lo12:buffer
    mov x2, #4096
    mov x8, #SYS_read
    svc #0

    // x0 = bytes leídos
    cmp x0, #0
    beq fin_lectura               // EOF
    blt salida_error              // error de lectura

    mov x24, #0                   // índice i = 0
    mov x25, x0                   // total bytes en bloque

procesar_byte:
    cmp x24, x25
    b.ge leer_bloque

    adrp x1, buffer
    add x1, x1, :lo12:buffer
    ldrb w26, [x1, x24]
    add x24, x24, #1

    // Si es salto de línea, clasificar número actual
    cmp w26, #10                  // '\n'
    b.eq fin_numero

    // Si es dígito ('0'..'9'), acumular
    cmp w26, #'0'
    b.lt procesar_byte
    cmp w26, #'9'
    b.gt procesar_byte

    // numero_actual = numero_actual * 10 + (byte - '0')
    mov x27, #10
    mul x22, x22, x27
    sub w26, w26, #'0'
    uxtw x26, w26
    add x22, x22, x26
    mov x23, #1
    b procesar_byte

fin_numero:
    // Solo clasificar si efectivamente hubo al menos un dígito
    cbz x23, reiniciar_numero

    mov x0, x22
    bl clasificar_codigo

reiniciar_numero:
    mov x22, #0
    mov x23, #0
    b procesar_byte

fin_lectura:
    // EOF con número pendiente (sin '\n' final)
    cbz x23, imprimir_reporte
    mov x0, x22
    bl clasificar_codigo

imprimir_reporte:
    // Encabezado
    adrp x0, msg_titulo
    add x0, x0, :lo12:msg_titulo
    bl write_cstr

    // "Éxitos 2xx: " + valor + "\n"
    adrp x0, msg_2xx
    add x0, x0, :lo12:msg_2xx
    bl write_cstr
    mov x0, x19
    bl print_uint
    adrp x0, msg_fin_linea
    add x0, x0, :lo12:msg_fin_linea
    bl write_cstr

    // "Errores 4xx: " + valor + "\n"
    adrp x0, msg_4xx
    add x0, x0, :lo12:msg_4xx
    bl write_cstr
    mov x0, x20
    bl print_uint
    adrp x0, msg_fin_linea
    add x0, x0, :lo12:msg_fin_linea
    bl write_cstr

    // "Errores 5xx: " + valor + "\n"
    adrp x0, msg_5xx
    add x0, x0, :lo12:msg_5xx
    bl write_cstr
    mov x0, x21
    bl print_uint
    adrp x0, msg_fin_linea
    add x0, x0, :lo12:msg_fin_linea
    bl write_cstr

salida_ok:
    mov x0, #0
    mov x8, #SYS_exit
    svc #0

salida_error:
    mov x0, #1
    mov x8, #SYS_exit
    svc #0

// -----------------------------------------------------------------------------
// clasificar_codigo(x0 = codigo_http)
// Incrementa el contador correspondiente: 2xx, 4xx o 5xx.
// -----------------------------------------------------------------------------
clasificar_codigo:
    cmp x0, #200
    b.lt clasificar_fin
    cmp x0, #299
    b.gt revisar_4xx
    add x19, x19, #1
    b clasificar_fin

revisar_4xx:
    cmp x0, #400
    b.lt clasificar_fin
    cmp x0, #499
    b.gt revisar_5xx
    add x20, x20, #1
    b clasificar_fin

revisar_5xx:
    cmp x0, #500
    b.lt clasificar_fin
    cmp x0, #599
    b.gt clasificar_fin
    add x21, x21, #1

clasificar_fin:
    ret

// -----------------------------------------------------------------------------
// write_cstr(x0 = puntero a string terminado en '\0')
// Imprime una cadena C usando syscall write.
// -----------------------------------------------------------------------------
write_cstr:
    mov x9, x0                    // guardar puntero inicial
    mov x10, #0                   // longitud = 0

wc_len_loop:
    ldrb w11, [x9, x10]
    cbz w11, wc_len_done
    add x10, x10, #1
    b wc_len_loop

wc_len_done:
    mov x1, x9                    // buffer
    mov x2, x10                   // tamaño
    mov x0, #STDOUT_FD            // fd
    mov x8, #SYS_write
    svc #0
    ret

// -----------------------------------------------------------------------------
// print_uint(x0 = entero sin signo)
// Convierte a ASCII en base 10 e imprime con syscall write.
// -----------------------------------------------------------------------------
print_uint:
    // Caso especial: número 0
    cbnz x0, pu_convertir
    adrp x1, num_buf
    add x1, x1, :lo12:num_buf
    mov w2, #'0'
    strb w2, [x1]
    mov x0, #STDOUT_FD
    mov x2, #1
    mov x8, #SYS_write
    svc #0
    ret

pu_convertir:
    adrp x12, num_buf
    add x12, x12, :lo12:num_buf
    add x12, x12, #31             // escribir de atrás hacia adelante
    mov w13, #0
    strb w13, [x12]               // terminador no indispensable, útil para depurar

    mov x14, #10
    mov x15, #0                   // contador de dígitos

pu_loop:
    udiv x16, x0, x14             // x16 = x0 / 10
    msub x17, x16, x14, x0        // x17 = x0 - (x16*10) => residuo
    add x17, x17, #'0'

    sub x12, x12, #1
    strb w17, [x12]
    add x15, x15, #1

    mov x0, x16
    cbnz x0, pu_loop

    // write(STDOUT_FD, x12, x15)
    mov x1, x12
    mov x2, x15
    mov x0, #STDOUT_FD
    mov x8, #SYS_write
    svc #0
    ret
*/

/*
Autor: Ramirez Gonzalez Benjamin
Curso: Arquitectura de Computadoras / Ensamblador ARM64
Práctica: Mini Cloud Log Analyzer - VARIANTE B (Código más frecuente)
Fecha: 21 de abril de 2026
Descripción: Identifica el código HTTP que más veces aparece en la entrada.
*/

.equ SYS_read,   63
.equ SYS_write,  64
.equ SYS_exit,   93
.equ STDIN_FD,    0
.equ STDOUT_FD,   1

.section .bss
    .align 4
buffer:         .skip 4096
num_buf:        .skip 32
// Tabla para contar frecuencias: 600 entradas de 8 bytes (64-bit c/u)
tabla_frec:     .skip 600 * 8 

.section .data
msg_titulo:     .asciz "=== Analizador de Logs: Variante B (Moda) ===\n"
msg_resultado:  .asciz "Código más frecuente: "
msg_veces:      .asciz " (Apariciones: "
msg_parentesis: .asciz ")\n"
msg_vacio:      .asciz "No se procesaron códigos válidos.\n"

.section .text
.global _start

_start:
    mov x22, #0                  // numero_actual
    mov x23, #0                  // tiene_digitos flag

leer_bloque:
    mov x0, #STDIN_FD
    adrp x1, buffer
    add x1, x1, :lo12:buffer
    mov x2, #4096
    mov x8, #SYS_read
    svc #0

    cmp x0, #0
    beq buscar_moda               // Al llegar al fin, calcular resultado
    blt salida_error

    mov x24, #0                   // i = 0
    mov x25, x0                   // total bytes
procesar_byte:
    cmp x24, x25
    b.ge leer_bloque
    adrp x1, buffer
    add x1, x1, :lo12:buffer
    ldrb w26, [x1, x24]
    add x24, x24, #1

    cmp w26, #10
    b.eq fin_numero

    cmp w26, #'0'
    b.lt procesar_byte
    cmp w26, #'9'
    b.gt procesar_byte

    mov x27, #10
    mul x22, x22, x27
    sub w26, w26, #'0'
    add x22, x22, x26
    mov x23, #1
    b procesar_byte

fin_numero:
    cbz x23, reiniciar_numero
    bl registrar_frecuencia
reiniciar_numero:
    mov x22, #0
    mov x23, #0
    b procesar_byte

// --- Lógica de conteo ---
registrar_frecuencia:
    // Solo aceptamos códigos entre 100 y 599 para evitar desbordar el buffer
    cmp x22, #100
    b.lt reg_fin
    cmp x22, #599
    b.gt reg_fin

    adrp x1, tabla_frec
    add x1, x1, :lo12:tabla_frec
    // desplazamiento = x22 * 8 (cada contador es de 8 bytes)
    lsl x2, x22, #3 
    ldr x3, [x1, x2]
    add x3, x3, #1
    str x3, [x1, x2]
reg_fin:
    ret

// --- Encontrar el máximo ---
buscar_moda:
    // EOF con número pendiente
    cbz x23, iniciar_busqueda
    bl registrar_frecuencia

iniciar_busqueda:
    mov x19, #0                  // max_frecuencia
    mov x20, #0                  // codigo_ganador
    mov x21, #100                // iterador i = 100

loop_busqueda:
    cmp x21, #600
    b.ge imprimir_resultado

    adrp x1, tabla_frec
    add x1, x1, :lo12:tabla_frec
    lsl x2, x21, #3
    ldr x3, [x1, x2]             // x3 = frecuencia de i

    cmp x3, x19
    b.le siguiente_i
    mov x19, x3                  // nuevo max_frecuencia
    mov x20, x21                 // nuevo codigo_ganador

siguiente_i:
    add x21, x21, #1
    b loop_busqueda

imprimir_resultado:
    cbz x19, reporte_vacio

    adrp x0, msg_titulo
    add x0, x0, :lo12:msg_titulo
    bl write_cstr

    adrp x0, msg_resultado
    add x0, x0, :lo12:msg_resultado
    bl write_cstr

    mov x0, x20                  // Imprimir código ganador
    bl print_uint

    adrp x0, msg_veces
    add x0, x0, :lo12:msg_veces
    bl write_cstr

    mov x0, x19                  // Imprimir cuántas veces
    bl print_uint

    adrp x0, msg_parentesis
    add x0, x0, :lo12:msg_parentesis
    bl write_cstr
    b salida_ok

reporte_vacio:
    adrp x0, msg_vacio
    add x0, x0, :lo12:msg_vacio
    bl write_cstr

salida_ok:
    mov x0, #0
    mov x8, #SYS_exit
    svc #0

salida_error:
    mov x0, #1
    mov x8, #SYS_exit
    svc #0

// --- Funciones auxiliares (write_cstr y print_uint se mantienen igual) ---

write_cstr:
    mov x9, x0
    mov x10, #0
wc_loop:
    ldrb w11, [x9, x10]
    cbz w11, wc_done
    add x10, x10, #1
    b wc_loop
wc_done:
    mov x1, x9
    mov x2, x10
    mov x0, #STDOUT_FD
    mov x8, #SYS_write
    svc #0
    ret

print_uint:
    cbnz x0, pu_conv
    mov w2, #'0'
    adrp x1, num_buf
    add x1, x1, :lo12:num_buf
    strb w2, [x1]
    mov x2, #1
    mov x0, #STDOUT_FD
    mov x8, #SYS_write
    svc #0
    ret
pu_conv:
    adrp x12, num_buf
    add x12, x12, :lo12:num_buf
    add x12, x12, #31
    mov x14, #10
    mov x15, #0
pu_loop:
    udiv x16, x0, x14
    msub x17, x16, x14, x0
    add x17, x17, #'0'
    sub x12, x12, #1
    strb w17, [x12]
    add x15, x15, #1
    mov x0, x16
    cbnz x0, pu_loop
    mov x1, x12
    mov x2, x15
    mov x0, #STDOUT_FD
    mov x8, #SYS_write
    svc #0
    ret
