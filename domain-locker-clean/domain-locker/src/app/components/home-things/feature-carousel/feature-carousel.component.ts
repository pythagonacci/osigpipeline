import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { PrimeNgModule } from '~/app/prime-ng.module';
import { DlIconComponent } from '~/app/components/misc/svg-icon.component';
import { features } from '~/app/pages/about/data/feature-comparison';

@Component({
  selector: 'app-feature-carousel',
  standalone: true,
  imports: [
    CommonModule,
    PrimeNgModule,
    DlIconComponent,
  ],
  templateUrl: './feature-carousel.component.html',
  styleUrls: ['./feature-carousel.component.scss'],
})
export class FeatureCarouselComponent {
  features = features;
}
