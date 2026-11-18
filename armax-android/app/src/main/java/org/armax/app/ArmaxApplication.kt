package org.armax.app

import android.app.Application

/** Guarda el contexto de la aplicación para que la capa nativa pueda mostrar errores en el idioma del teléfono. */
class ArmaxApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Armax.init(this)
    }
}
