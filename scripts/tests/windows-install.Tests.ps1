Import-Module Pester -ErrorAction Stop
. "$PSScriptRoot\..\windows-install.ps1"

Describe 'PMACS Windows install helpers' {
    It 'prefers the stable installed exe over Cargo target output' {
        $root = 'C:\repo\pmacs-utils'
        $localAppData = 'C:\Users\Tester\AppData\Local'

        $resolved = Resolve-PmacsExePath -ProjectRoot $root -LocalAppData $localAppData -StableExists $true -BuildExists $true

        $resolved | Should Be 'C:\Users\Tester\AppData\Local\Programs\PMACS VPN\pmacs-vpn.exe'
    }

    It 'falls back to the release build when no stable installed exe exists yet' {
        $root = 'C:\repo\pmacs-utils'
        $localAppData = 'C:\Users\Tester\AppData\Local'

        $resolved = Resolve-PmacsExePath -ProjectRoot $root -LocalAppData $localAppData -StableExists $false -BuildExists $true

        $resolved | Should Be 'C:\repo\pmacs-utils\target\release\pmacs-vpn.exe'
    }

    It 'uses the stable install path as the destination when neither file exists yet' {
        $root = 'C:\repo\pmacs-utils'
        $localAppData = 'C:\Users\Tester\AppData\Local'

        $resolved = Resolve-PmacsExePath -ProjectRoot $root -LocalAppData $localAppData -StableExists $false -BuildExists $false

        $resolved | Should Be 'C:\Users\Tester\AppData\Local\Programs\PMACS VPN\pmacs-vpn.exe'
    }
}
