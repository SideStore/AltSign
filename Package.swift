// swift-tools-version:5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import Foundation
import PackageDescription

let package = Package(
    name: "AltSign",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
    ],
    products: [
        .library(
            name: "AltSign-Dynamic",
            type: .dynamic,
            targets: ["AltSign", "CAltSign", "CoreCrypto", "CCoreCrypto", "ldid", "ldid-core", "OpenSSL"]
        ),
        .library(
            name: "AltSign-Static",
			type: .static,
            targets: ["AltSign", "CAltSign", "CoreCrypto", "CCoreCrypto", "ldid", "ldid-core"]
        )
    ],


    //TODO: make targets use binaries as dependencies rather than compile from source
    dependencies: [
//         .package(url: "https://github.com/krzyzanowskim/OpenSSL.git", .upToNextMinor(from: "1.1.180")),
//         .package(url: "https://github.com/SideStore/iMobileDevice.swift", .upToNextMinor(from: "1.0.4"))
    ],





    targets: [
        // exposing OpenSSL as target
        .binaryTarget(
            name: "OpenSSL",
            path: "Dependencies/OpenSSL/Frameworks/OpenSSL.xcframework"
        ),

        .target(
            name: "AltSign",
            dependencies: [
                "CAltSign"
            ],
            path: "AltSign/Sources",
            cSettings: [
                .headerSearchPath("Dependencies/minizip"),
                .define("CORECRYPTO_DONOT_USE_TRANSPARENT_UNION=1"),
            ]
//             swiftSettings: [
//                 .define("MARKETPLACE")
//             ]
        ),

//        .testTarget(
//            name: "AltSignTests",
//            dependencies: ["AltSign"]
//        ),


        .target(
            name: "CAltSign",
            dependencies: [
                "CoreCrypto",
                "ldid",
//                 "minizip"
            ],
            path: "",
            exclude: [
                "AltSign/ldid/alt_ldid.cpp",
                "AltSign/ldid/alt_ldid.hpp",
                "AltSign/Sources",
                "AltSign/include/module.modulemap",
                "Dependencies/corecrypto",
                "Dependencies/ldid",
                "Dependencies/OpenSSL",
                "Dependencies/minizip/iowin32.c",
                "Dependencies/minizip/Makefile",
                "Dependencies/minizip/minizip.c",
                "Dependencies/minizip/miniunz.c",
            ],
            publicHeadersPath: "AltSign/include",
            cSettings: [
                // Recursive wildcard paths no longer work as of Xcode 16 :(
                // .headerSearchPath("AltSign/**"),
                .headerSearchPath("AltSign/include"),
                .headerSearchPath("AltSign/include/AltSign"),
                .headerSearchPath("AltSign/Capabilities"),
                .headerSearchPath("Dependencies/ldid"),
                .headerSearchPath("Dependencies/ldid/libplist/include"),
                .headerSearchPath("Dependencies/minizip"),
                .headerSearchPath("Dependencies/OpenSSL/ios/include"),
                .define("unix=1"),
            ],
            // multiple language targets are unsupported by xcode 16 ?!
            cxxSettings: [
                .headerSearchPath("AltSign/include"),
                .headerSearchPath("AltSign/include/AltSign"),
                .headerSearchPath("AltSign/Capabilities"),
                .headerSearchPath("Dependencies/ldid"),
                .headerSearchPath("Dependencies/ldid/libplist/include"),
                .headerSearchPath("Dependencies/minizip"),
                .headerSearchPath("Dependencies/OpenSSL/ios/include"),
             .define("unix=1"),
            ],
            linkerSettings: [
                .linkedFramework("UIKit", .when(platforms: [.iOS])),
                .linkedFramework("Security"),
            ]
        ),




        .target(
            name: "ldid-core",
            // dependencies: [
            //     "OpenSSL",
            //     .product(name: "libplist", package: "iMobileDevice.swift")
            // ],
            path: "Dependencies/ldid",
            exclude: [
                "ldid.hpp",
                "ldid.cpp",
                "version.sh",
                "COPYING",
                "control.sh",
                "control",
                "ios.sh",
                "make.sh",
                "deb.sh",
                "plist.sh",

                // if lib plist is included as dependency, then no need for source
                "libplist/include",
                "libplist/include/Makefile.am",
                "libplist/fuzz",
                "libplist/cython",
                "libplist/m4",
                "libplist/test",
                "libplist/tools",
                "libplist/AUTHORS",
                "libplist/autogen.sh",
                "libplist/configure.ac",
                "libplist/COPYING",
                "libplist/COPYING.LESSER",
                "libplist/doxygen.cfg.in",
                "libplist/Makefile.am",
                "libplist/NEWS",
                "libplist/README.md",
                "libplist/src/Makefile.am",
                "libplist/src/libplist++.pc.in",
                "libplist/src/libplist.pc.in",
                "libplist/libcnary/cnary.c",
                "libplist/libcnary/COPYING",
                "libplist/libcnary/Makefile.am",
                "libplist/libcnary/README"
            ],
            sources: [
                "lookup2.c",
                "libplist/src",
                "libplist/libcnary"
            ],
            publicHeadersPath: "",
            cSettings: [
                .headerSearchPath("libplist/include"),
                .headerSearchPath("libplist/src"),
                .headerSearchPath("libplist/libcnary/include"),
//                .headerSearchPath("../OpenSSL/ios/include"),

                .unsafeFlags(["-w"])
            ],
            cxxSettings: [
                .unsafeFlags(["-w"])
            ]
        ),

        .target(
            name: "ldid",
            dependencies: ["ldid-core"],
            path: "AltSign/ldid",
            exclude: [
                "alt_ldid.hpp"
            ],
            sources: [
                "alt_ldid.cpp"
            ],
            publicHeadersPath: "",
            cSettings: [
                .headerSearchPath("../../Dependencies/ldid"),
                .headerSearchPath("../../Dependencies/ldid/libplist/include"),
                .headerSearchPath("../../Dependencies/ldid/libplist/src"),
                .headerSearchPath("../../Dependencies/ldid/libplist/libcnary/include"),
//                .headerSearchPath("../../Dependencies/OpenSSL/ios/include"),
            ],
            cxxSettings: [
                .unsafeFlags(["-w"])
            ]
        ),

        .target(
            name: "CCoreCrypto",
            path: "Dependencies/corecrypto",
            exclude: [
                "Sources/CoreCryptoMacros.swift"
            ],
            cSettings: [
                .headerSearchPath("include/corecrypto"),
                .define("CORECRYPTO_DONOT_USE_TRANSPARENT_UNION=1")
            ]
        ),

        .target(
            name: "CoreCrypto",
            dependencies: ["CCoreCrypto"],
            path: "Dependencies/corecrypto/Sources",
            exclude: [
                "ccsrp.m"
            ],
            sources: [
                "CoreCryptoMacros.swift"
            ],
            cSettings: [
                .define("CORECRYPTO_DONOT_USE_TRANSPARENT_UNION=1")
            ]
        ),

        // MARK: - minizip

        .target(
            name: "minizip",
            path : "Dependencies/minizip"
            sources: [
                "minizip/zip.c",
                "minizip/unzip.c",
                "minizip/ioapi.c"
            ],
            publicHeadersPath: ""
        )
    ],

    cLanguageStandard: CLanguageStandard.gnu11,
    cxxLanguageStandard: .cxx14
)
