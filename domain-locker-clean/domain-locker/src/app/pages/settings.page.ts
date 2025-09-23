import { Component, OnInit, ViewChild, ElementRef, PLATFORM_ID, Inject } from '@angular/core';
import { Router, RouterOutlet } from '@angular/router';
import { PrimeNgModule } from '~/app/prime-ng.module';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { MenuItem } from 'primeng/api';
import { settingsLinks } from '~/app/constants/navigation-links';
import { SupabaseService } from '~/app/services/supabase.service';
import { ProfilePictureComponent } from '~/app/components/misc/profile-picture.component';
import { FeatureService } from '../services/features.service';
import { FeatureNotEnabledComponent } from '~/app/components/misc/feature-not-enabled.component';
import DatabaseService from '~/app/services/database.service';

@Component({
  standalone: true,
  imports: [CommonModule, RouterOutlet, PrimeNgModule, ProfilePictureComponent, FeatureNotEnabledComponent],
  templateUrl: './settings/index.page.html',
})
export default class SettingsIndexPage implements OnInit {
  items: MenuItem[] | undefined;
  hideSideBar = false;
  @ViewChild('sidebarNav', { static: false }) sidebarNav!: ElementRef;
  hideTextLabels = false;

  databaseServiceType = '';
  settingsEnabled$ = this.featureService.isFeatureEnabled('accountSettings');

  constructor(
    private router: Router,
    private featureService: FeatureService,
    public supabaseService: SupabaseService,
    public databaseService: DatabaseService,
    @Inject(PLATFORM_ID) private platformId: Object,
  ) {}

  ngOnInit() {
    this.items = settingsLinks;
    this.databaseServiceType = this.databaseService.serviceType;
  }

  isActive(link: string): boolean {
    return this.router.url === link;
  }

  async logout() {
    await this.supabaseService.signOut();
    window.location.href = '/login';
  }

  toggleSideBar() {
    this.hideSideBar = !this.hideSideBar;
  }

  ngAfterViewInit() {
    if (isPlatformBrowser(this.platformId)) {
      this.checkWindowSize();
      window.addEventListener('resize', this.checkWindowSize.bind(this));
    }
  }

  ngOnDestroy() { 
    if (isPlatformBrowser(this.platformId)) {
      window.removeEventListener('resize', this.checkWindowSize.bind(this));
    }
  }

  checkWindowSize() {
    if (window && window.innerWidth < 768) {
      this.hideSideBar = true;
    } else {
      this.hideSideBar = false;
    }
  }
}
