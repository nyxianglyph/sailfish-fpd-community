# Sailfish Fingerprint Daemon - Community Edition

## This branch: AIDL fingerprint HALs over libgbinder

Branch `gbinder-aidl` replaces the libhybris bridge to the Android-side
`libbiometry_fp_api` library (HIDL 2.x only) with an implementation on top of
libgbinder (`src/hardware/biometry_fp_gbinder.c`). It is meant for devices
whose vendor image only ships the AIDL HAL
`android.hardware.biometrics.fingerprint.IFingerprint` (Android 13 and later).

- Nothing has to be built in an Android tree: no `libbiometry_fp_api`, no
  `droid-biometry-fp` package, no `fake_crypt`. Build the RPM in the Sailfish
  SDK; it needs `libgbinder-devel`, `glib2-devel` and the Qt5 Core/DBus
  development packages.
- The auth token for enrolling comes from the AIDL Gatekeeper
  (`android.hardware.gatekeeper.IGatekeeper/default`).
- At start the daemon performs the `ISharedSecret` negotiation that keystore2
  does on Android. Without it Gatekeeper cannot produce auth tokens.
- If `vendor.xiaomi.hardware.fingerprintextension.IXiaomiFingerprint/default`
  is present, the daemon reports running operations to it. Xiaomi's
  `mfp-daemon` only lights an under-display sensor when it has been told so;
  it then handles touch detection and illumination itself.
- The HAL instance defaults to `default`; set `FPD_HAL_INSTANCE` in the
  service environment for another one.
- Fingerprints are stored by the HAL for Android user 0.

On the device, `sailfish-devicelock-fpd` has to replace
`jolla-devicelock-plugin-encsfa`/`-encpartition`; those have no fingerprint
client.

Tested on the Xiaomi 14T (`degas`, MT6897, Android 14 vendor, Goodix optical
under-display sensor): enrolling from Settings and unlocking work. The parcel
layouts follow the AIDL definitions, with UBports' biometryd as a reference.
Not tested on any other device.

The build instructions below describe the HIDL version on `master` and do not
apply to this branch.

This daemon implements the DBUS API of the Jolla sailfish-fpd packge, and can be used with sailfish-devicelock-fpd
to add fingerprint support to community ports.

While sailfish-fpd is available in the repositories, it requires a closed, device specific sailfish-fpd-slave
package which talks to the hardware.  In this implementation, the daemon itself talks to the hardware using
an android library, inspired from biometryd from Ubuntu Touch, by Erfan Abdi (https://github.com/erfanoabdi/biometryd)

Some of the code from biometryd has been copied into this project.  That code is licensed under the LGPLv3 and 
retains its header information.

Reverse engineering was performed using:
 * dbus-monitor --system "interface=org.sailfishos.fingerprint1"
   * This show the correct ordering of method calls from the various clients
 * running "strings" on the sailfilsh-fpd binary
   * This gave a good hint to some of the return variables and states
 * The soruces for mce, which talks to the daemon and whose code is open and available
   * This gave solid function definitions and some of the enums used
  
## How to build for a device

### Android Library/Binary

In HADK:

    git clone https://github.com/sailfishos-open/sailfish-fpd-community.git hybris/mw/sailfish-fpd-community
    source build/envsetup.sh
    export USE_CCACHE=1
    lunch aosp_$DEVICE-user (or appropriate name)
    make libbiometry_fp_api (or libbiometry_fp_api_32 for 32bit ports)
    
If the device uses keymaster 4, then an additional service called fake_crypt is required

    git clone https://github.com/erfanoabdi/fake_crypt.git external/fake_crypt
    make fake_crypt
    
Copy the android parts for packaging

    hybris/mw/sailfish-fpd-community/rpm/copy-hal.sh

In SDK:

    rpm/dhd/helpers/build_packages.sh --build=hybris/mw/sailfish-fpd-community --spec=rpm/droid-biometry-fp.spec --do-not-install
    
If fake_crypt is required

    rpm/dhd/helpers/build_packages.sh --build=hybris/mw/sailfish-fpd-community --spec=rpm/droid-fake-crypt.spec --do-not-install


### Daemon

in SDK:

    rpm/dhd/helpers/build_packages.sh --build=hybris/mw/sailfish-fpd-community

## Testing

While the daemon is known to work on several devices, it may sometimes be possible to test the daemon without
using the sailfish settings page.  For this, a seperate GUI application has been developed to exercise
the DBUS API.  This application can be built from the following sources:
https://github.com/sailfishos-open/sailfish-fpd-community-test
