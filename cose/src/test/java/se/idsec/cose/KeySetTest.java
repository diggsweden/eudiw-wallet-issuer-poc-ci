/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.cose;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class KeySetTest extends TestBase {

    /**
     * Test of stream method of class KeySet.
     *
     * @throws CoseException
     */
    @Test
    public void testStream() throws CoseException {
        KeySet ks = new KeySet();
        COSEKey ecdsa_256 = COSEKey.generateKey(AlgorithmID.ECDSA_256);
        ks.add(ecdsa_256);
        ks.add(COSEKey.generateKey(AlgorithmID.ECDSA_512));

        KeySet newKeys = ks.stream()
                .filter(k -> k.HasAlgorithmID(AlgorithmID.ECDSA_256))
                .collect(new KeySetCollector());
        List<COSEKey> filteredKeys = newKeys.getList();
        Assert.assertEquals(1, filteredKeys.size());
        Assert.assertEquals(ecdsa_256, filteredKeys.get(0));

        newKeys = ks.stream()
                .filter(k -> AlgorithmID.ECDSA_256.AsCBOR().equals(k.get(KeyKeys.Algorithm)))
                .collect(new KeySetCollector());
        filteredKeys = newKeys.getList();
        Assert.assertEquals(1, filteredKeys.size());
        Assert.assertEquals(ecdsa_256, filteredKeys.get(0));

        newKeys = ks.stream()
                .filter(k -> k.HasAlgorithmID(AlgorithmID.ECDSA_384))
                .collect(new KeySetCollector());
        filteredKeys = newKeys.getList();
        Assert.assertEquals(0, filteredKeys.size());
    }

}
