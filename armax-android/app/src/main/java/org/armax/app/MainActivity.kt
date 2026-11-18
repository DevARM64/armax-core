package org.armax.app

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.delay
import java.text.DateFormat
import java.util.Date
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ArmaxTheme {
                ArmaxApp()
            }
        }
    }
}

@Composable
fun ArmaxApp(vm: MainViewModel = viewModel()) {
    val phase by vm.phase.collectAsStateWithLifecycle()
    val message by vm.message.collectAsStateWithLifecycle()

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        when (phase) {
            Phase.Loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            Phase.Onboarding -> OnboardingScreen(vm)
            Phase.Backup -> BackupScreen(vm)
            Phase.Home -> HomeScreen(vm)
        }
    }
    message?.let { m ->
        AlertDialog(
            onDismissRequest = { vm.dismissMessage() },
            confirmButton = { TextButton(onClick = { vm.dismissMessage() }) { Text(stringResource(R.string.ok)) } },
            text = { SelectionContainer { Text(m) } },
        )
    }
}

// ----------------------------------------------------------------------------------------------
// Primera vez: crear o restaurar la cartera
// ----------------------------------------------------------------------------------------------

@Composable
fun OnboardingScreen(vm: MainViewModel) {
    val busy by vm.busy.collectAsStateWithLifecycle()
    var restoring by rememberSaveable { mutableStateOf(false) }
    var phrase by rememberSaveable { mutableStateOf("") }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(40.dp))
        Logo(size = 72.dp)
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.tagline), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Panel {
            Text(stringResource(R.string.dev_warning), style = MaterialTheme.typography.bodyMedium, color = warningColor())
        }
        if (!restoring) {
            Button(onClick = { vm.createWallet() }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.create_wallet))
            }
            OutlinedButton(onClick = { restoring = true }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.restore_with_phrase))
            }
        } else {
            OutlinedTextField(
                value = phrase,
                onValueChange = { phrase = it },
                label = { Text(stringResource(R.string.phrase_label)) },
                modifier = Modifier.fillMaxWidth(),
                minLines = 3,
            )
            Button(onClick = { vm.restoreWallet(phrase) }, enabled = !busy && phrase.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.restore))
            }
            TextButton(onClick = { restoring = false; phrase = "" }) { Text(stringResource(R.string.back)) }
        }
        if (busy) CircularProgressIndicator()
    }
}

@Composable
fun BackupScreen(vm: MainViewModel) {
    val mnemonic by vm.mnemonic.collectAsStateWithLifecycle()
    var saved by rememberSaveable { mutableStateOf(false) }

    // la frase no se puede capturar ni aparece en la vista de apps recientes mientras esta pantalla está abierta
    val activity = LocalContext.current as? Activity
    DisposableEffect(Unit) {
        activity?.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { activity?.window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }

    val words = (mnemonic ?: "").trim().split(" ").filter { it.isNotEmpty() }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(24.dp))
        Text(stringResource(R.string.backup_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.backup_body), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Panel {
            words.chunked(3).forEachIndexed { r, row ->
                Row(Modifier.fillMaxWidth()) {
                    row.forEachIndexed { c, w ->
                        Text(
                            "${r * 3 + c + 1}. $w",
                            modifier = Modifier.weight(1f),
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodyLarge,
                        )
                    }
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = saved, onCheckedChange = { saved = it })
            Text(stringResource(R.string.backup_confirm))
        }
        Button(onClick = { vm.confirmBackup() }, enabled = saved, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.continue_label))
        }
    }
}

// ----------------------------------------------------------------------------------------------
// Pantalla principal
// ----------------------------------------------------------------------------------------------

@Composable
fun HomeScreen(vm: MainViewModel) {
    var tab by rememberSaveable { mutableStateOf(0) }
    val titles = listOf(R.string.nav_dashboard, R.string.nav_history, R.string.nav_receive, R.string.nav_send, R.string.nav_settings)
    val icons = listOf(R.drawable.ic_nav_dashboard, R.drawable.ic_nav_history, R.drawable.ic_nav_receive, R.drawable.ic_nav_send, R.drawable.ic_nav_settings)
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                titles.forEachIndexed { i, t ->
                    NavigationBarItem(
                        selected = tab == i,
                        onClick = { tab = i },
                        icon = { Icon(painterResource(icons[i]), contentDescription = null) },
                        label = { Text(stringResource(t)) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.primary,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                            indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                            unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        ),
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (tab) {
                0 -> DashboardTab(vm)
                1 -> HistoryTab(vm)
                2 -> ReceiveTab(vm)
                3 -> SendTab(vm)
                else -> SettingsTab(vm)
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------
// Panel
// ----------------------------------------------------------------------------------------------

@Composable
private fun toneColor(severity: Int) = when (severity) {
    0 -> MaterialTheme.colorScheme.secondary
    1 -> warningColor()
    else -> MaterialTheme.colorScheme.error
}

@Composable
fun DashboardTab(vm: MainViewModel) {
    val running by NodeState.running.collectAsStateWithLifecycle()
    val status by NodeState.status.collectAsStateWithLifecycle()
    val error by NodeState.error.collectAsStateWithLifecycle()
    val hashrates by NodeState.hashrates.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { _ -> vm.startNode() }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Logo(size = 36.dp)
            Spacer(Modifier.width(10.dp))
            Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Spacer(Modifier.weight(1f))
            val net = status?.network ?: settings.network
            Chip(
                stringResource(
                    when (net) {
                        "fast" -> R.string.network_fast
                        "testnet" -> R.string.network_testnet
                        else -> R.string.network_devnet
                    },
                ),
                MaterialTheme.colorScheme.primary,
            )
        }

        if (!running) {
            Button(
                onClick = {
                    val needs = Build.VERSION.SDK_INT >= 33 &&
                        ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                    if (needs) permission.launch(Manifest.permission.POST_NOTIFICATIONS) else vm.startNode()
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.node_start)) }
        } else {
            OutlinedButton(onClick = { vm.stopNode() }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.node_stop)) }
        }
        error?.let { Text(stringResource(R.string.error_prefix, it), color = MaterialTheme.colorScheme.error) }

        val s = status
        if (s == null) {
            Panel {
                Text(
                    stringResource(if (running) R.string.node_starting else R.string.node_offline),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            BalancePanel(s)
            MiningPanel(s, hashrates)
            NetworkPanel(s)
            s.pool?.let { PoolPanel(it, s.miner) }
        }
    }
}

@Composable
private fun BalancePanel(s: NodeStatus) {
    Panel(title = stringResource(R.string.balance)) {
        val txt = formatArm(s.balance)
        Row(verticalAlignment = Alignment.Bottom) {
            Text(
                txt,
                style = BigNumberStyle.copy(fontSize = if (txt.length > 14) 22.sp else 30.sp),
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.unit_arm),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(bottom = 3.dp),
            )
        }
        val maturing = ((s.balance ?: 0L) - (s.spendable ?: 0L)).coerceAtLeast(0L)
        StatRow {
            Stat(stringResource(R.string.spendable), formatArm(s.spendable), Modifier.weight(1f))
            Stat(stringResource(R.string.maturing), formatArm(maturing), Modifier.weight(1f))
        }
    }
}

@Composable
private fun MiningPanel(s: NodeStatus, hashrates: List<Float>) {
    val ctx = LocalContext.current
    val m = s.miner
    Panel(title = stringResource(R.string.mining)) {
        if (m == null) {
            Text(stringResource(R.string.reason_NoGovernor), color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("%.1f".format(m.hashrate), style = BigNumberStyle, color = MaterialTheme.colorScheme.onSurface)
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.unit_hs), style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.weight(1f))
                Chip(reasonLabel(ctx, m.reason), toneColor(reasonSeverity(m.reason)))
            }
            Sparkline(hashrates, MaterialTheme.colorScheme.primary, Modifier.fillMaxWidth().height(56.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.temperature), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(m.batteryTempC?.let { "%.1f °C".format(it) } ?: "—", style = MaterialTheme.typography.bodySmall)
            }
            TempBar(m.batteryTempC)
            StatRow {
                Stat(stringResource(R.string.threads), m.threads.toString(), Modifier.weight(1f))
                Stat(stringResource(R.string.blocks_found), m.blocks.toString(), Modifier.weight(1f))
                Stat(stringResource(R.string.shares_found), m.sharesFound.toString(), Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun NetworkPanel(s: NodeStatus) {
    Panel(title = stringResource(R.string.network)) {
        StatRow {
            Stat(stringResource(R.string.height), s.height.toString(), Modifier.weight(1f))
            Stat(stringResource(R.string.peers), "${s.readyPeers}/${s.peers}", Modifier.weight(1f))
            Stat(stringResource(R.string.mempool), s.mempool.toString(), Modifier.weight(1f))
        }
        Chip(
            stringResource(if (s.syncing) R.string.syncing else R.string.synced),
            if (s.syncing) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondary,
        )
    }
}

@Composable
private fun PoolPanel(p: PoolStatus, miner: MinerStatus?) {
    Panel(title = stringResource(R.string.pool_title)) {
        val ppm = p.myPpm
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Bottom) {
            Text(ppm?.let { "%.2f %%".format(it / 10_000.0) } ?: "—", style = BigNumberStyle, color = MaterialTheme.colorScheme.onSurface)
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.your_share),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 4.dp),
            )
        }
        LinearProgressIndicator(
            progress = { ((ppm ?: 0L) / 1_000_000f).coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth(),
            color = MaterialTheme.colorScheme.secondary,
            trackColor = MaterialTheme.colorScheme.surfaceVariant,
        )
        StatRow {
            Stat(stringResource(R.string.shares_in_chain), p.shares.toString(), Modifier.weight(1f))
            Stat(stringResource(R.string.shares_found), (miner?.sharesFound ?: 0L).toString(), Modifier.weight(1f))
        }
    }
}

// ----------------------------------------------------------------------------------------------
// Historial
// ----------------------------------------------------------------------------------------------

private fun shortAddr(a: String): String = if (a.length > 20) a.take(10) + "…" + a.takeLast(6) else a

@Composable
private fun timeText(ts: Long?): String =
    if (ts == null) stringResource(R.string.pending)
    else DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(ts * 1000))

@Composable
fun HistoryTab(vm: MainViewModel) {
    val running by NodeState.running.collectAsStateWithLifecycle()
    val items by vm.history.collectAsStateWithLifecycle()
    val clipboard = LocalClipboardManager.current

    // mientras la pestaña está abierta y el nodo corre, se relee cada 5 s
    LaunchedEffect(running) {
        while (running) {
            vm.refreshHistory()
            delay(5_000)
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.history_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        if (!running) {
            Text(stringResource(R.string.history_stopped), color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else if (items.isEmpty()) {
            Text(stringResource(R.string.history_empty), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        items.forEach { e ->
            val incoming = e.kind == "mined" || e.kind == "received"
            val title = stringResource(
                when (e.kind) {
                    "mined" -> R.string.kind_mined
                    "received" -> R.string.kind_received
                    "sent" -> R.string.kind_sent
                    else -> R.string.kind_internal
                },
            )
            val icon = when (e.kind) {
                "mined" -> R.drawable.ic_kind_mined
                "received" -> R.drawable.ic_nav_receive
                "sent" -> R.drawable.ic_nav_send
                else -> R.drawable.ic_kind_internal
            }
            val tone = when (e.kind) {
                "mined" -> MaterialTheme.colorScheme.primary
                "received" -> MaterialTheme.colorScheme.secondary
                "sent" -> MaterialTheme.colorScheme.error
                else -> MaterialTheme.colorScheme.onSurfaceVariant
            }
            val sign = if (e.kind == "internal") "" else if (incoming) "+" else "−"
            val state = when {
                e.height == null -> stringResource(R.string.pending_confirm)
                e.kind == "mined" && e.maturesIn > 0 -> stringResource(R.string.matures_in, e.maturesIn, e.confirmations)
                else -> stringResource(R.string.confirmations_block, e.confirmations, e.height)
            }
            Panel {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier.size(40.dp).background(tone.copy(alpha = 0.16f), CircleShape),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(painterResource(icon), contentDescription = null, tint = tone, modifier = Modifier.size(20.dp))
                    }
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(title, style = MaterialTheme.typography.titleMedium)
                        Text(timeText(e.timestamp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text("$sign${formatArm(e.amount)}", style = MidNumberStyle, color = tone)
                        Text(stringResource(R.string.unit_arm), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Text(state, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                e.fee?.let {
                    Text(
                        stringResource(R.string.fee_label, formatArm(it)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                e.counterparty?.let {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            stringResource(if (e.kind == "sent") R.string.to_addr else R.string.from_addr, shortAddr(it)),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        TextButton(onClick = { clipboard.setText(AnnotatedString(it)) }) { Text(stringResource(R.string.copy_address)) }
                    }
                }
                e.txid?.let {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            stringResource(R.string.id_label, it.take(10) + "…"),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                        TextButton(onClick = { clipboard.setText(AnnotatedString(it)) }) { Text(stringResource(R.string.copy_id)) }
                    }
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------
// Recibir
// ----------------------------------------------------------------------------------------------

@Composable
fun ReceiveTab(vm: MainViewModel) {
    val address by vm.address.collectAsStateWithLifecycle()
    val clipboard = LocalClipboardManager.current
    val ctx = LocalContext.current
    val shareTitle = stringResource(R.string.share_address)

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.receive_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.receive_body), color = MaterialTheme.colorScheme.onSurfaceVariant)
        address?.let {
            QrCode(
                text = it,
                contentDescription = stringResource(R.string.receive_qr_desc),
                modifier = Modifier.fillMaxWidth(0.7f).align(Alignment.CenterHorizontally),
            )
        }
        Panel(title = stringResource(R.string.your_address)) {
            SelectionContainer {
                Text(
                    address ?: "—",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        }
        Button(
            onClick = { address?.let { clipboard.setText(AnnotatedString(it)) } },
            enabled = address != null,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.copy_address)) }
        OutlinedButton(
            onClick = {
                address?.let { a ->
                    val send = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, a)
                    }
                    ctx.startActivity(Intent.createChooser(send, shareTitle))
                }
            },
            enabled = address != null,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.share)) }
    }
}

// ----------------------------------------------------------------------------------------------
// Enviar
// ----------------------------------------------------------------------------------------------

@Composable
fun SendTab(vm: MainViewModel) {
    val busy by vm.busy.collectAsStateWithLifecycle()
    val status by NodeState.status.collectAsStateWithLifecycle()
    var to by rememberSaveable { mutableStateOf("") }
    var amount by rememberSaveable { mutableStateOf("") }
    var fee by rememberSaveable { mutableStateOf("") }
    var confirm by remember { mutableStateOf(false) }
    var scanInvalid by remember { mutableStateOf(false) }
    val scanPrompt = stringResource(R.string.scan_prompt)
    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        val raw = result.contents
        if (raw != null) {
            val addr = parseScannedAddress(raw)
            if (addr != null) { to = addr; scanInvalid = false } else scanInvalid = true
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.send_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(
            stringResource(R.string.send_spendable, formatArm(status?.spendable)),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = to,
            onValueChange = { to = it.trim() },
            label = { Text(stringResource(R.string.send_to)) },
            modifier = Modifier.fillMaxWidth(),
            minLines = 2,
        )
        OutlinedButton(
            onClick = {
                scanInvalid = false
                scanner.launch(
                    ScanOptions().apply {
                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        setPrompt(scanPrompt)
                        setBeepEnabled(false)
                        setOrientationLocked(true)
                    },
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.scan_button)) }
        if (scanInvalid) Text(stringResource(R.string.scan_invalid), color = MaterialTheme.colorScheme.error)
        OutlinedTextField(
            value = amount,
            onValueChange = { amount = it },
            label = { Text(stringResource(R.string.send_amount)) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
        )
        OutlinedTextField(
            value = fee,
            onValueChange = { fee = it.filter { c -> c.isDigit() } },
            label = { Text(stringResource(R.string.send_fee)) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        )
        Button(
            onClick = { confirm = true },
            enabled = !busy && to.isNotBlank() && amount.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.send_button)) }
        if (busy) CircularProgressIndicator()
        Text(stringResource(R.string.send_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }

    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text(stringResource(R.string.send_confirm_title)) },
            text = { Text(stringResource(R.string.send_confirm_body, amount, to)) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = false
                    vm.send(to, amount, fee)
                }) { Text(stringResource(R.string.send_action)) }
            },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

// ----------------------------------------------------------------------------------------------
// Ajustes
// ----------------------------------------------------------------------------------------------

@Composable
fun SettingsTab(vm: MainViewModel) {
    val saved by vm.settings.collectAsStateWithLifecycle()
    var network by remember(saved) { mutableStateOf(saved.network) }
    var connect by remember(saved) { mutableStateOf(saved.connect) }
    var pin by remember(saved) { mutableStateOf(saved.pin) }
    var mine by remember(saved) { mutableStateOf(saved.mine) }
    var pool by remember(saved) { mutableStateOf(saved.pool) }
    var anyPower by remember(saved) { mutableStateOf(saved.anyPower) }
    var minBattery by remember(saved) { mutableIntStateOf(saved.minBattery) }
    var screenOn by remember(saved) { mutableStateOf(saved.mineWithScreenOn) }
    var threads by remember(saved) { mutableStateOf(saved.threads.toString()) }
    val ctx = LocalContext.current

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.settings_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.settings_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

        Panel(title = stringResource(R.string.settings_network_section)) {
            SwitchRow(stringResource(R.string.settings_testnet), network == "fast") { network = if (it) "fast" else "testnet" }
            OutlinedTextField(
                value = connect,
                onValueChange = { connect = it },
                label = { Text(stringResource(R.string.settings_connect)) },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = pin,
                onValueChange = { pin = it },
                label = { Text(stringResource(R.string.settings_pin)) },
                modifier = Modifier.fillMaxWidth(),
            )
        }

        Panel(title = stringResource(R.string.settings_mining_section)) {
            SwitchRow(stringResource(R.string.settings_mine), mine) { mine = it }
            SwitchRow(stringResource(R.string.settings_pool), pool) { pool = it }
            SwitchRow(stringResource(R.string.settings_any_power), anyPower) { anyPower = it }
            if (anyPower) {
                Text(stringResource(R.string.settings_min_battery, minBattery))
                Slider(value = minBattery.toFloat(), onValueChange = { minBattery = it.toInt() }, valueRange = 0f..100f)
            }
            SwitchRow(stringResource(R.string.settings_screen_on), screenOn) { screenOn = it }
            OutlinedTextField(
                value = threads,
                onValueChange = { threads = it.filter { c -> c.isDigit() }.take(2) },
                label = { Text(stringResource(R.string.settings_threads)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
            Text(
                stringResource(R.string.settings_governor_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Button(
            onClick = {
                vm.saveSettings(
                    Settings(
                        network = network,
                        connect = connect,
                        pin = pin,
                        mine = mine,
                        pool = pool,
                        anyPower = anyPower,
                        minBattery = minBattery,
                        mineWithScreenOn = screenOn,
                        threads = (threads.toIntOrNull() ?: 1).coerceIn(1, 4),
                    )
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.settings_save)) }

        Panel(title = stringResource(R.string.settings_language_section)) {
            Text(
                stringResource(R.string.settings_language_system),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (Build.VERSION.SDK_INT >= 33) {
                OutlinedButton(onClick = { openLanguageSettings(ctx) }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.settings_language_change))
                }
            }
        }

        Panel(title = stringResource(R.string.settings_about_section)) {
            val coreVersion = remember { runCatching { Armax.version() }.getOrDefault("?") }
            Text(stringResource(R.string.settings_core_version, coreVersion), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.dev_warning), style = MaterialTheme.typography.bodySmall, color = warningColor())
        }
    }
}

/** Ajuste de idioma por app (Android 13+). */
private fun openLanguageSettings(ctx: Context) {
    val intent = Intent(android.provider.Settings.ACTION_APP_LOCALE_SETTINGS, Uri.parse("package:" + ctx.packageName))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { ctx.startActivity(intent) }
}

@Composable
private fun SwitchRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}


/** Acepta el texto de un QR: la dirección sola, o con prefijo `armax:` y parámetros (`?amount=…`). Devuelve null si no parece una dirección ARMax. */
internal fun parseScannedAddress(raw: String): String? {
    val t = raw.trim().let { if (it.startsWith("armax:", ignoreCase = true)) it.substring(6) else it }
        .substringBefore('?').trim()
    return if (t.startsWith("arm1") && t.length in 20..120 && t.all { it.isLetterOrDigit() }) t else null
}
