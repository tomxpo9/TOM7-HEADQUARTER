import turtle
import colorsys

# Inisialisasi turtle
t = turtle.Turtle()
s = turtle.Screen()

# Pengaturan awal
t.speed(0) # Kecepatan tercepat
t.pensize(1)
s.bgcolor('black')

h = 0.0 # Nilai hue awal untuk colorsys

# Loop untuk menggambar pola
for i in range(250): # Menggunakan 250 seperti di gambar, bukan 258
    c = colorsys.hsv_to_rgb(h, 1, 1) # Konversi HSV ke RGB (Saturation 1, Value 1)
    t.pencolor(c)
    h += 0.1 # Increment hue untuk perubahan warna
    t.circle(5 - i, 100) # Circle dengan radius yang berkurang, sudut 100
    t.lt(80) # Belok kiri 80 derajat
    t.circle(5 - i, 100) # Circle lagi dengan radius yang berkurang, sudut 100
    t.rt(100) # Belok kanan 100 derajat

turtle.done() # Menjaga jendela tetap terbuka sampai ditutup secara manual
