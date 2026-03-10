package ifneeded SpirentTestCenter $env(STC_VERSION) [list source [file join $env(STC_INSTALL_DIR) SpirentTestCenter.tcl]]
package ifneeded stclib $env(STC_VERSION) [list source [file join $env(STC_INSTALL_DIR) stclib.tcl]]
