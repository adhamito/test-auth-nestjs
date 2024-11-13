import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './users.entity';
import { Repository } from 'typeorm';

@Injectable()
export class AppService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async create(data: any) {
    return this.userRepository.save(data);
  }

  async findOne(conditions: Partial<User>) {
    return this.userRepository.findOne({ where: conditions });
  }
}
