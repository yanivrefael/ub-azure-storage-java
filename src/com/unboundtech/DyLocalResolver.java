package com.unboundtech;

import com.microsoft.azure.keyvault.core.IKey;
import com.microsoft.azure.keyvault.core.IKeyResolver;
import org.apache.commons.lang3.concurrent.ConcurrentUtils;

import java.io.IOException;
import java.security.*;
import java.util.concurrent.Future;

public class DyLocalResolver  implements IKeyResolver {


    @Override
    public Future<IKey> resolveKeyAsync(String s) {
        KeyStore ks = null;
        try {
            DyRSAKey dyRSAKey = new DyRSAKey(s);
            dyRSAKey.load();
            return ConcurrentUtils.constantFuture((IKey) dyRSAKey);

        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
