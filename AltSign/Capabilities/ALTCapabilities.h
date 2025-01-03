//
//  ALTCapabilities.h
//  AltSign
//
//  Created by Riley Testut on 6/25/19.
//  Copyright © 2019 Riley Testut. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Entitlements
typedef NSString *ALTEntitlement NS_TYPED_EXTENSIBLE_ENUM;
extern ALTEntitlement const ALTEntitlementApplicationIdentifier;
extern ALTEntitlement const ALTEntitlementKeychainAccessGroups;
extern ALTEntitlement const ALTEntitlementAppGroups;
extern ALTEntitlement const ALTEntitlementGetTaskAllow;
extern ALTEntitlement const ALTEntitlementIncreasedMemoryLimit;
extern ALTEntitlement const ALTEntitlementTeamIdentifier;
extern ALTEntitlement const ALTEntitlementInterAppAudio;
extern ALTEntitlement const ALTEntitlementIncreasedDebuggingMemoryLimit;
extern ALTEntitlement const ALTEntitlementExtendedVirtualAddressing;

// Capabilities
typedef NSString *ALTCapability NS_TYPED_EXTENSIBLE_ENUM;
extern ALTCapability const ALTCapabilityIncreasedMemoryLimit;
extern ALTCapability const ALTCapabilityIncreasedDebuggingMemoryLimit;
extern ALTCapability const ALTCapabilityExtendedVirtualAddressing;

// Features
typedef NSString *ALTFeature NS_TYPED_EXTENSIBLE_ENUM;
extern ALTFeature const ALTFeatureGameCenter;
extern ALTFeature const ALTFeatureAppGroups;
extern ALTFeature const ALTFeatureInterAppAudio;

_Nullable ALTEntitlement ALTEntitlementForFeature(ALTFeature feature) NS_SWIFT_NAME(ALTEntitlement.init(feature:));
_Nullable ALTFeature ALTFeatureForEntitlement(ALTEntitlement entitlement) NS_SWIFT_NAME(ALTFeature.init(entitlement:));
bool ALTFreeDeveloperCanUseEntitlement(ALTEntitlement entitlement);

NS_ASSUME_NONNULL_END
