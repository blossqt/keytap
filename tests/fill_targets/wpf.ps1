# A WPF login box (TextBox, PasswordBox), shown without taking the keyboard.
#   wpf_target.ps1 <report file> <seconds> <x> <y>
param([string]$Out, [double]$Seconds, [int]$X, [int]$Y)
Add-Type -AssemblyName PresentationFramework
$w = New-Object System.Windows.Window
$w.Title = 'WPF login'; $w.Width = 340; $w.Height = 230; $w.Left = $X; $w.Top = $Y
$w.ShowActivated = $false; $w.WindowStartupLocation = 'Manual'
$panel = New-Object System.Windows.Controls.StackPanel
$l1 = New-Object System.Windows.Controls.Label; $l1.Content = 'Email'
$tb = New-Object System.Windows.Controls.TextBox
[System.Windows.Automation.AutomationProperties]::SetName($tb, 'Email')
$l2 = New-Object System.Windows.Controls.Label; $l2.Content = 'Password'
$pb = New-Object System.Windows.Controls.PasswordBox
[System.Windows.Automation.AutomationProperties]::SetName($pb, 'Password')
$btn = New-Object System.Windows.Controls.Button; $btn.Content = 'Log in'
$script:state = ''
$btn.Add_Click({ $script:state = 'submitted' })
foreach ($c in $l1, $tb, $l2, $pb, $btn) { [void]$panel.Children.Add($c) }
$w.Content = $panel
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(100)
$start = Get-Date
$timer.Add_Tick({
    @{ u = $tb.Text; p = $pb.Password; s = $script:state } | ConvertTo-Json -Compress | Set-Content -Path $Out -Encoding UTF8
    if (((Get-Date) - $start).TotalSeconds -gt $Seconds) { $w.Close() }
})
$w.Add_ContentRendered({
    $h = (New-Object System.Windows.Interop.WindowInteropHelper($w)).Handle
    [Console]::Out.WriteLine('{"hwnd": ' + [int64]$h + '}'); [Console]::Out.Flush()
})
$timer.Start()
[void]$w.ShowDialog()
