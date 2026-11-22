package io.nexomesh.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NexoMeshProtocolTest {
    @Test
    fun parseHostPortAcceptsValidAndRejectsMeshOrBlank() {
        assertEquals("192.168.1.10" to 51820, MeshVpnService.parseHostPort("192.168.1.10", 51820))
        assertEquals("189.191.93.120" to 51744, MeshVpnService.parseHostPort("189.191.93.120:51744", 51820))
        assertNull(MeshVpnService.parseHostPort("", 51820))
        assertNull(MeshVpnService.parseHostPort("STUN directo", 51820))
        assertNull(MeshVpnService.parseHostPort("0.0.0.0:51820", 51820))
        assertNull(MeshVpnService.parseHostPort("10.0.0.2:51820", 51820))
    }

    @Test
    fun formattingHelperFormatsUnits() {
        assertEquals("512 B", FormattingHelper.formatBytes(512))
        assertEquals("1.0 KB", FormattingHelper.formatBytes(1024))
        assertEquals("1.0 MB", FormattingHelper.formatBytes(1024 * 1024))
    }
}
