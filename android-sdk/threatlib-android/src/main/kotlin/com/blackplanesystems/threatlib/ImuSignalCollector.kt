package com.blackplanesystems.threatlib

data class ImuFeatures(
    val varianceX: Float,
    val varianceY: Float,
    val varianceZ: Float,
    val breathingBandPower: Float,
    val tremorBandPower: Float,
    val sampleIntervalCv: Float
)

object ImuSignalCollector {
    fun compute(samples: List<Triple<Float, Float, Float>>, intervalsMs: List<Long>): ImuFeatures {
        val xs = samples.map { it.first }
        val ys = samples.map { it.second }
        val zs = samples.map { it.third }
        return ImuFeatures(
            varianceX = variance(xs),
            varianceY = variance(ys),
            varianceZ = variance(zs),
            breathingBandPower = 0.0f,
            tremorBandPower = 0.0f,
            sampleIntervalCv = coefficientOfVariation(intervalsMs.map { it.toFloat() })
        )
    }

    private fun variance(values: List<Float>): Float {
        if (values.isEmpty()) return 0.0f
        val mean = values.average().toFloat()
        return values.map { (it - mean) * (it - mean) }.average().toFloat()
    }

    private fun coefficientOfVariation(values: List<Float>): Float {
        if (values.isEmpty()) return 0.0f
        val mean = values.average().toFloat()
        if (mean == 0.0f) return 0.0f
        return kotlin.math.sqrt(variance(values)) / mean
    }
}
